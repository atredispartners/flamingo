package flamingo

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// MongoDBVersion is the server version reported by hello and buildInfo.
const MongoDBVersion = "7.0.14"

// MongoDBScramSalt is the fixed SCRAM salt sent to every client. SCRAM-SHA-1
// uses the first 16 bytes and SCRAM-SHA-256 all 28. A constant salt, like the
// fixed VNC and NTLM challenges, means the PBKDF2 work for a candidate
// password is done once and reused against every captured proof.
var MongoDBScramSalt = []byte{
	0x66, 0x6c, 0x61, 0x6d, 0x69, 0x6e, 0x67, 0x6f, 0x2d, 0x73, 0x63, 0x72, 0x61, 0x6d,
	0x2d, 0x73, 0x61, 0x6c, 0x74, 0x2d, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
}

// MongoDBScramNonce is the fixed server nonce suffix appended to the client
// nonce. With a constant suffix the AuthMessage depends only on values the
// client chose, so a recorded proof can be checked offline without any
// per-connection server state.
const MongoDBScramNonce = "ZmxhbWluZ29ub25jZTAwMDE="

// mongoTimeout is the idle deadline applied between client messages.
const mongoTimeout = 30 * time.Second

// MongoDB wire protocol opcodes and limits.
const (
	mongoOpReply      = 1
	mongoOpQuery      = 2004
	mongoOpCompressed = 2012
	mongoOpMsg        = 2013

	mongoMaxMessage    = 48 << 10
	mongoMaxCommands   = 24
	mongoMaxSections   = 8
	mongoMaxWireVer    = 21
	mongoScramIterSHA1 = 4096
	mongoScramIterSHA2 = 15000
)

// ConfMongoDB describes the options for a MongoDB capture service.
type ConfMongoDB struct {
	BindPort     uint16
	BindHost     string
	RecordWriter *RecordWriter
	shutdown     bool
	listener     net.Listener
	m            sync.Mutex
}

// NewConfMongoDB creates a default configuration for the MongoDB capture server.
func NewConfMongoDB() *ConfMongoDB {
	return &ConfMongoDB{
		BindPort: 27017,
		BindHost: "[::]",
	}
}

// IsShutdown checks to see if the service is shutting down.
func (c *ConfMongoDB) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down.
func (c *ConfMongoDB) Shutdown() {
	c.m.Lock()
	defer c.m.Unlock()
	if !c.shutdown {
		c.shutdown = true
		if c.listener != nil {
			c.listener.Close()
		}
	}
}

// SpawnMongoDB starts a logging MongoDB server.
func SpawnMongoDB(c *ConfMongoDB) error {
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", c.BindHost, c.BindPort))
	if err != nil {
		return err
	}
	log.Debugf("mongodb is listening on %s:%d", c.BindHost, c.BindPort)
	c.listener = listener
	go mongoStart(c)
	return nil
}

func mongoStart(c *ConfMongoDB) {
	for !c.IsShutdown() {
		conn, err := c.listener.Accept()
		if err != nil {
			continue
		}
		go mongoHandleConnection(c, conn)
	}
}

// mongoSession tracks the state of a single client connection.
type mongoSession struct {
	conf    *ConfMongoDB
	conn    net.Conn
	reader  *bufio.Reader
	reqID   int32
	process bsonObjectID
	client  map[string]string
	conv    *mongoScram
}

// mongoRequest is one decoded client message.
type mongoRequest struct {
	id     int32
	op     int32
	doc    bsonRaw
	db     string
	legacy bool
}

// mongoScram is an open SCRAM conversation awaiting the client proof.
type mongoScram struct {
	mech        string
	user        string
	clientFirst string
	serverFirst string
	clientNonce string
	nonce       string
	salt        []byte
	iter        int
}

// mongoHandleConnection answers commands until the client disconnects, the
// command budget is spent, or the connection idles out.
func mongoHandleConnection(c *ConfMongoDB, conn net.Conn) {
	defer conn.Close()

	s := &mongoSession{
		conf:   c,
		conn:   conn,
		reader: bufio.NewReader(conn),
		client: map[string]string{},
	}
	var seed [4]byte
	rand.Read(seed[:])
	s.reqID = int32(binary.LittleEndian.Uint32(seed[:]) & 0x3fffffff)
	rand.Read(s.process[:])

	defer s.recordAbandoned()
	for i := 0; i < mongoMaxCommands; i++ {
		conn.SetDeadline(time.Now().Add(mongoTimeout))
		req, err := s.read()
		if err != nil {
			return
		}
		if !s.handle(req) {
			return
		}
	}
}

// record logs a captured credential together with the client metadata.
func (s *mongoSession) record(fields map[string]string) {
	rec := map[string]string{
		"_server": fmt.Sprintf("%s:%d", s.conf.BindHost, s.conf.BindPort),
	}
	maps.Copy(rec, s.client)
	maps.Copy(rec, fields)
	s.conf.RecordWriter.Record("credential", "mongodb", s.conn.RemoteAddr().String(), rec)
}

// recordAbandoned logs the user name of a SCRAM conversation the client
// started but never completed.
func (s *mongoSession) recordAbandoned() {
	cv := s.conv
	if cv == nil {
		return
	}
	s.conv = nil
	s.record(map[string]string{
		"username":     cv.user,
		"method":       cv.mech,
		"client_nonce": cv.clientNonce,
	})
}

// read decodes the next OP_MSG or OP_QUERY message.
func (s *mongoSession) read() (*mongoRequest, error) {
	var hdr [16]byte
	if _, err := io.ReadFull(s.reader, hdr[:]); err != nil {
		return nil, err
	}
	le := binary.LittleEndian
	n := int32(le.Uint32(hdr[0:]))
	req := &mongoRequest{id: int32(le.Uint32(hdr[4:])), op: int32(le.Uint32(hdr[12:]))}
	if n < 16 || n > mongoMaxMessage {
		return nil, fmt.Errorf("bad message length %d", n)
	}
	body := make([]byte, n-16)
	if _, err := io.ReadFull(s.reader, body); err != nil {
		return nil, err
	}
	switch req.op {
	case mongoOpMsg:
		return req, mongoParseMsg(req, body)
	case mongoOpQuery:
		return req, mongoParseQuery(req, body)
	case mongoOpCompressed:
		return nil, errors.New("compressed message without negotiated compression")
	}
	return nil, fmt.Errorf("unsupported opcode %d", req.op)
}

// mongoParseMsg extracts the body document from an OP_MSG.
func mongoParseMsg(req *mongoRequest, b []byte) error {
	if len(b) < 5 {
		return errors.New("short OP_MSG")
	}
	flags := binary.LittleEndian.Uint32(b)
	b = b[4:]
	if flags&1 != 0 && len(b) >= 4 {
		b = b[:len(b)-4] // checksum
	}
	for i := 0; len(b) > 0 && i < mongoMaxSections; i++ {
		kind := b[0]
		b = b[1:]
		if len(b) < 4 {
			return errors.New("short OP_MSG section")
		}
		size := int(int32(binary.LittleEndian.Uint32(b)))
		if size < 5 || size > len(b) {
			return errors.New("bad OP_MSG section size")
		}
		switch kind {
		case 0:
			doc, err := bsonParse(b[:size])
			if err != nil {
				return fmt.Errorf("invalid body: %w", err)
			}
			req.doc = doc
		case 1:
		default:
			return fmt.Errorf("unknown section kind %d", kind)
		}
		b = b[size:]
	}
	if req.doc == nil {
		return errors.New("OP_MSG without body")
	}
	req.db, _ = req.doc.lookup("$db").str()
	return nil
}

// mongoParseQuery extracts the query document from a legacy OP_QUERY.
func mongoParseQuery(req *mongoRequest, b []byte) error {
	req.legacy = true
	if len(b) < 4 {
		return errors.New("short OP_QUERY")
	}
	b = b[4:]
	coll, rest, ok := strings.Cut(string(b), "\x00")
	if !ok || len(rest) < 8+5 {
		return errors.New("short OP_QUERY")
	}
	req.db, _, _ = strings.Cut(coll, ".")
	q := []byte(rest[8:])
	size := int(int32(binary.LittleEndian.Uint32(q)))
	if size < 5 || size > len(q) {
		return errors.New("bad OP_QUERY document size")
	}
	doc, err := bsonParse(q[:size])
	if err != nil {
		return fmt.Errorf("invalid query: %w", err)
	}
	if inner, ok := doc.lookup("$query").doc(); ok {
		doc = inner
	}
	req.doc = doc
	return nil
}

// handle answers one command and reports whether the session continues.
func (s *mongoSession) handle(req *mongoRequest) bool {
	name, _, ok := req.doc.first()
	if !ok {
		return s.reply(req, mongoFailure(59, "CommandNotFound", "no such command: ''"))
	}
	switch strings.ToLower(name) {
	case "hello", "ismaster":
		if v := req.doc.lookup("maxAwaitTimeMS"); v.typ != 0 && req.doc.lookup("topologyVersion").typ != 0 {
			ms, _ := v.int64()
			s.await(time.Duration(ms) * time.Millisecond)
		}
		return s.reply(req, s.hello(req, strings.ToLower(name) == "ismaster"))
	case "saslstart":
		return s.reply(req, s.saslStart(req.doc))
	case "saslcontinue":
		return s.reply(req, s.saslContinue(req.doc))
	case "authenticate":
		u, _ := req.doc.lookup("user").str()
		mech, _ := req.doc.lookup("mechanism").str()
		if mech == "" {
			mech = "MONGODB-X509"
		}
		if u != "" {
			s.record(map[string]string{"username": u, "method": mech})
		}
		return s.reply(req, mongoAuthFailed())
	case "ping", "endsessions":
		return s.reply(req, bsonDoc{bsonE("ok", 1.0)})
	case "buildinfo":
		return s.reply(req, mongoBuildInfo())
	}
	return s.reply(req, mongoFailure(13, "Unauthorized", fmt.Sprintf("Command %s requires authentication", name)))
}

// await holds an awaitable hello, as a server with no topology change would,
// until the client sends more data or the wait expires.
func (s *mongoSession) await(d time.Duration) {
	if d <= 0 || d > mongoTimeout {
		d = mongoTimeout
	}
	s.conn.SetReadDeadline(time.Now().Add(d))
	s.reader.Peek(1)
	s.conn.SetReadDeadline(time.Now().Add(mongoTimeout))
}

// hello builds the hello / isMaster reply of a MongoDB 7.0 standalone and
// handles speculative authentication carried inside the request.
func (s *mongoSession) hello(req *mongoRequest, legacy bool) bsonDoc {
	if cl, ok := req.doc.lookup("client").doc(); ok && len(s.client) == 0 {
		s.clientMeta(cl)
	}
	d := bsonDoc{}
	if ok, _ := req.doc.lookup("helloOk").boolean(); ok {
		d = append(d, bsonE("helloOk", true))
	}
	if legacy {
		d = append(d, bsonE("ismaster", true))
	} else {
		d = append(d, bsonE("isWritablePrimary", true))
	}
	d = append(d,
		bsonE("topologyVersion", bsonDoc{bsonE("processId", s.process), bsonE("counter", int64(0))}),
		bsonE("maxBsonObjectSize", int32(16777216)),
		bsonE("maxMessageSizeBytes", int32(48000000)),
		bsonE("maxWriteBatchSize", int32(100000)),
		bsonE("localTime", time.Now()),
		bsonE("logicalSessionTimeoutMinutes", int32(30)),
		bsonE("connectionId", int32(s.reqID%100000+1)),
		bsonE("minWireVersion", int32(0)),
		bsonE("maxWireVersion", int32(mongoMaxWireVer)),
		bsonE("readOnly", false),
	)
	if _, ok := req.doc.lookup("saslSupportedMechs").str(); ok {
		d = append(d, bsonE("saslSupportedMechs", bsonArray{"SCRAM-SHA-1", "SCRAM-SHA-256"}))
	}
	if spec, ok := req.doc.lookup("speculativeAuthenticate").doc(); ok {
		var r bsonDoc
		if _, ok := spec.lookup("saslStart").int64(); ok {
			r = s.saslStart(spec)
		} else if _, ok := spec.lookup("authenticate").int64(); ok {
			mech, _ := spec.lookup("mechanism").str()
			u, _ := spec.lookup("user").str()
			if mech == "" {
				mech = "MONGODB-X509"
			}
			if u != "" {
				s.record(map[string]string{"username": u, "method": mech})
			}
		}
		if len(r) > 0 && r[0].key == "conversationId" {
			d = append(d, bsonE("speculativeAuthenticate", r[:len(r)-1])) // without "ok"
		}
	}
	return append(d, bsonE("ok", 1.0))
}

// clientMeta keeps the driver handshake metadata for credential records.
func (s *mongoSession) clientMeta(cl bsonRaw) {
	keep := func(field string, path ...string) {
		if v, ok := cl.lookupPath(path...).str(); ok && v != "" {
			s.client[field] = v
		}
	}
	keep("driver", "driver", "name")
	keep("driver_version", "driver", "version")
	keep("application_name", "application", "name")
	keep("os", "os", "type")
	keep("platform", "platform")
}

// saslStart begins a SASL conversation. PLAIN yields the cleartext
// credential immediately; SCRAM returns server-first and waits for the proof.
func (s *mongoSession) saslStart(doc bsonRaw) bsonDoc {
	s.recordAbandoned()
	mech, _ := doc.lookup("mechanism").str()
	payload := doc.lookup("payload").bytes()
	switch mech {
	case "SCRAM-SHA-1", "SCRAM-SHA-256":
		bare, ok := mongoGS2Strip(payload)
		if !ok {
			return mongoAuthFailed()
		}
		attrs := mongoScramAttrs(bare)
		if attrs["r"] == "" {
			return mongoAuthFailed()
		}
		cv := &mongoScram{
			mech:        mech,
			user:        mongoScramUnescape(attrs["n"]),
			clientFirst: bare,
			clientNonce: attrs["r"],
			nonce:       attrs["r"] + MongoDBScramNonce,
			iter:        mongoScramIterSHA2,
			salt:        MongoDBScramSalt,
		}
		if mech == "SCRAM-SHA-1" {
			cv.iter, cv.salt = mongoScramIterSHA1, MongoDBScramSalt[:16]
		}
		cv.serverFirst = fmt.Sprintf("r=%s,s=%s,i=%d", cv.nonce, base64.StdEncoding.EncodeToString(cv.salt), cv.iter)
		s.conv = cv
		return bsonDoc{
			bsonE("conversationId", int32(1)),
			bsonE("done", false),
			bsonE("payload", bsonBinary(cv.serverFirst)),
			bsonE("ok", 1.0),
		}
	case "PLAIN":
		// The payload is "[authzid]\x00authcid\x00password".
		parts := strings.SplitN(string(payload), "\x00", 3)
		if len(parts) == 3 {
			fields := map[string]string{
				"username": parts[1],
				"password": parts[2],
				"method":   mech,
			}
			if parts[0] != "" {
				fields["authzid"] = parts[0]
			}
			s.record(fields)
		}
	}
	return mongoAuthFailed()
}

// saslContinue receives client-final and records everything needed to check
// the proof offline: SCRAM-SHA-256 hashes the password as sent, SCRAM-SHA-1
// hashes the hex MD5 of "user:mongo:password".
func (s *mongoSession) saslContinue(doc bsonRaw) bsonDoc {
	cv := s.conv
	s.conv = nil
	if cv == nil {
		return mongoFailure(17, "ProtocolError", "No SASL session state found")
	}
	msg := string(doc.lookup("payload").bytes())
	i := strings.LastIndex(msg, ",p=")
	if i < 0 {
		s.record(map[string]string{
			"username":     cv.user,
			"method":       cv.mech,
			"client_nonce": cv.clientNonce,
		})
		return mongoAuthFailed()
	}
	withoutProof := msg[:i]
	attrs := mongoScramAttrs(withoutProof)
	s.record(map[string]string{
		"username":        cv.user,
		"method":          cv.mech,
		"client_nonce":    cv.clientNonce,
		"server_nonce":    cv.nonce,
		"salt":            base64.StdEncoding.EncodeToString(cv.salt),
		"iterations":      strconv.Itoa(cv.iter),
		"channel_binding": attrs["c"],
		"client_proof":    msg[i+3:],
		"auth_message":    cv.clientFirst + "," + cv.serverFirst + "," + withoutProof,
	})
	return mongoAuthFailed()
}

// mongoGS2Strip removes the GS2 header ("n,," or "y,," with an optional
// authzid) from client-first.
func mongoGS2Strip(p []byte) (string, bool) {
	s := string(p)
	i := strings.Index(s, ",")
	if i < 0 {
		return "", false
	}
	j := strings.Index(s[i+1:], ",")
	if j < 0 {
		return "", false
	}
	return s[i+j+2:], true
}

// mongoScramAttrs splits a SCRAM message into its single-letter attributes.
func mongoScramAttrs(s string) map[string]string {
	m := map[string]string{}
	for i, part := range strings.Split(s, ",") {
		if i >= 16 {
			break
		}
		if k, v, ok := strings.Cut(part, "="); ok && len(k) == 1 {
			m[k] = v
		}
	}
	return m
}

// mongoScramUnescape decodes the SCRAM user name escapes.
func mongoScramUnescape(s string) string {
	return strings.NewReplacer("=2C", ",", "=3D", "=").Replace(s)
}

func mongoAuthFailed() bsonDoc {
	return mongoFailure(18, "AuthenticationFailed", "Authentication failed.")
}

// mongoFailure builds a command error reply.
func mongoFailure(code int32, name, msg string) bsonDoc {
	return bsonDoc{bsonE("ok", 0.0), bsonE("errmsg", msg), bsonE("code", code), bsonE("codeName", name)}
}

// mongoBuildInfo builds the buildInfo reply.
func mongoBuildInfo() bsonDoc {
	var arr bsonArray
	for _, p := range strings.Split(MongoDBVersion, ".") {
		n, _ := strconv.Atoi(p)
		arr = append(arr, int32(n))
	}
	arr = append(arr, int32(0))
	return bsonDoc{
		bsonE("version", MongoDBVersion),
		bsonE("gitVersion", "ce59cfc6a3c5e5c067dca0d30697edd68d4f5188"),
		bsonE("modules", bsonArray{}),
		bsonE("allocator", "tcmalloc"),
		bsonE("javascriptEngine", "mozjs"),
		bsonE("sysInfo", "deprecated"),
		bsonE("versionArray", arr),
		bsonE("bits", int32(64)),
		bsonE("debug", false),
		bsonE("maxBsonObjectSize", int32(16777216)),
		bsonE("storageEngines", bsonArray{"devnull", "inMemory", "wiredTiger"}),
		bsonE("ok", 1.0),
	}
}

// reply sends a document as OP_MSG, or OP_REPLY for legacy OP_QUERY requests,
// and reports whether the write succeeded.
func (s *mongoSession) reply(req *mongoRequest, d bsonDoc) bool {
	doc := d.marshal()
	s.reqID++
	le := binary.LittleEndian
	b := make([]byte, 16, 64+len(doc))
	le.PutUint32(b[4:], uint32(s.reqID))
	le.PutUint32(b[8:], uint32(req.id))
	if req.legacy {
		le.PutUint32(b[12:], mongoOpReply)
		b = le.AppendUint32(b, 8) // AwaitCapable
		b = le.AppendUint64(b, 0) // cursor
		b = le.AppendUint32(b, 0) // starting from
		b = le.AppendUint32(b, 1) // number returned
	} else {
		le.PutUint32(b[12:], mongoOpMsg)
		b = le.AppendUint32(b, 0)
		b = append(b, 0)
	}
	b = append(b, doc...)
	le.PutUint32(b[0:], uint32(len(b)))
	_, err := s.conn.Write(b)
	return err == nil
}

// BSON element types handled by the minimal codec.
const (
	bsonTypeDouble    = 0x01
	bsonTypeString    = 0x02
	bsonTypeDocument  = 0x03
	bsonTypeArray     = 0x04
	bsonTypeBinary    = 0x05
	bsonTypeUndefined = 0x06
	bsonTypeObjectID  = 0x07
	bsonTypeBool      = 0x08
	bsonTypeDateTime  = 0x09
	bsonTypeNull      = 0x0a
	bsonTypeRegex     = 0x0b
	bsonTypeDBPointer = 0x0c
	bsonTypeCode      = 0x0d
	bsonTypeSymbol    = 0x0e
	bsonTypeCodeScope = 0x0f
	bsonTypeInt32     = 0x10
	bsonTypeTimestamp = 0x11
	bsonTypeInt64     = 0x12
	bsonTypeDecimal   = 0x13
	bsonTypeMaxKey    = 0x7f
	bsonTypeMinKey    = 0xff
)

// bsonMaxDepth bounds document nesting accepted from clients.
const bsonMaxDepth = 16

// errBSON reports a malformed document.
var errBSON = errors.New("bson: malformed document")

// bsonDoc is an ordered list of elements used to build documents.
type bsonDoc []bsonElem

// bsonElem is one key/value pair of a bsonDoc. Supported values are
// float64, string, bsonDoc, bsonArray, bsonBinary, bsonObjectID, bool,
// time.Time, int32 and int64.
type bsonElem struct {
	key string
	val any
}

// bsonArray encodes as a BSON array.
type bsonArray []any

// bsonBinary encodes as generic (subtype 0) binary data.
type bsonBinary []byte

// bsonObjectID encodes as a 12-byte ObjectId.
type bsonObjectID [12]byte

// bsonE builds a document element.
func bsonE(key string, val any) bsonElem {
	return bsonElem{key: key, val: val}
}

// marshal encodes the document.
func (d bsonDoc) marshal() []byte {
	out := make([]byte, 4)
	for _, el := range d {
		out = bsonAppend(out, el.key, el.val)
	}
	out = append(out, 0)
	binary.LittleEndian.PutUint32(out, uint32(len(out)))
	return out
}

// bsonAppend encodes one element onto out.
func bsonAppend(out []byte, key string, v any) []byte {
	le := binary.LittleEndian
	tag := func(t byte) {
		out = append(out, t)
		out = append(out, key...)
		out = append(out, 0)
	}
	switch x := v.(type) {
	case float64:
		tag(bsonTypeDouble)
		out = le.AppendUint64(out, math.Float64bits(x))
	case string:
		tag(bsonTypeString)
		out = le.AppendUint32(out, uint32(len(x)+1))
		out = append(out, x...)
		out = append(out, 0)
	case bsonDoc:
		tag(bsonTypeDocument)
		out = append(out, x.marshal()...)
	case bsonArray:
		d := make(bsonDoc, len(x))
		for i, item := range x {
			d[i] = bsonE(strconv.Itoa(i), item)
		}
		tag(bsonTypeArray)
		out = append(out, d.marshal()...)
	case bsonBinary:
		tag(bsonTypeBinary)
		out = le.AppendUint32(out, uint32(len(x)))
		out = append(out, 0)
		out = append(out, x...)
	case bsonObjectID:
		tag(bsonTypeObjectID)
		out = append(out, x[:]...)
	case bool:
		tag(bsonTypeBool)
		if x {
			out = append(out, 1)
		} else {
			out = append(out, 0)
		}
	case time.Time:
		tag(bsonTypeDateTime)
		out = le.AppendUint64(out, uint64(x.UnixMilli()))
	case int32:
		tag(bsonTypeInt32)
		out = le.AppendUint32(out, uint32(x))
	case int64:
		tag(bsonTypeInt64)
		out = le.AppendUint64(out, uint64(x))
	default:
		tag(bsonTypeNull)
	}
	return out
}

// bsonRaw is a validated, encoded BSON document.
type bsonRaw []byte

// bsonValue is one decoded element: its type tag and raw value bytes. A
// zero typ means the element was not found.
type bsonValue struct {
	typ  byte
	data []byte
}

// bsonParse validates b as a complete document, including every nested
// document, before it is used.
func bsonParse(b []byte) (bsonRaw, error) {
	return bsonRaw(b), bsonValidate(b, 0)
}

// bsonValidate walks a document and checks every element's bounds.
func bsonValidate(b []byte, depth int) error {
	if depth > bsonMaxDepth {
		return errBSON
	}
	return bsonRaw(b).walk(func(key string, v bsonValue) (bool, error) {
		switch v.typ {
		case bsonTypeDocument, bsonTypeArray:
			return true, bsonValidate(v.data, depth+1)
		case bsonTypeCodeScope:
			if len(v.data) < 4 {
				return false, errBSON
			}
			rest := v.data[4:]
			n, err := bsonValueSize(bsonTypeString, rest)
			if err != nil {
				return false, err
			}
			return true, bsonValidate(rest[n:], depth+1)
		}
		return true, nil
	})
}

// walk calls fn for each top-level element until fn returns false or an
// error. Framing errors are returned as errBSON.
func (d bsonRaw) walk(fn func(key string, v bsonValue) (bool, error)) error {
	if len(d) < 5 {
		return errBSON
	}
	n := int(int32(binary.LittleEndian.Uint32(d)))
	if n != len(d) || d[n-1] != 0 {
		return errBSON
	}
	b := d[4 : n-1]
	for len(b) > 0 {
		typ := b[0]
		b = b[1:]
		i := bytes.IndexByte(b, 0)
		if i < 0 {
			return errBSON
		}
		key := string(b[:i])
		b = b[i+1:]
		size, err := bsonValueSize(typ, b)
		if err != nil {
			return err
		}
		more, err := fn(key, bsonValue{typ: typ, data: b[:size]})
		if err != nil || !more {
			return err
		}
		b = b[size:]
	}
	return nil
}

// bsonValueSize returns the encoded length of a value of type typ at the
// start of b, checking that b holds all of it.
func bsonValueSize(typ byte, b []byte) (int, error) {
	le := binary.LittleEndian
	fixed := func(n int) (int, error) {
		if len(b) < n {
			return 0, errBSON
		}
		return n, nil
	}
	str := func(b []byte) (int, error) {
		if len(b) < 4 {
			return 0, errBSON
		}
		n := int(int32(le.Uint32(b)))
		if n < 1 || n > len(b)-4 || b[4+n-1] != 0 {
			return 0, errBSON
		}
		return 4 + n, nil
	}
	switch typ {
	case bsonTypeDouble, bsonTypeDateTime, bsonTypeTimestamp, bsonTypeInt64:
		return fixed(8)
	case bsonTypeString, bsonTypeCode, bsonTypeSymbol:
		return str(b)
	case bsonTypeDocument, bsonTypeArray, bsonTypeCodeScope:
		if len(b) < 5 {
			return 0, errBSON
		}
		n := int(int32(le.Uint32(b)))
		if n < 5 || n > len(b) {
			return 0, errBSON
		}
		return n, nil
	case bsonTypeBinary:
		if len(b) < 5 {
			return 0, errBSON
		}
		n := int(int32(le.Uint32(b)))
		if n < 0 || n > len(b)-5 {
			return 0, errBSON
		}
		return 5 + n, nil
	case bsonTypeUndefined, bsonTypeNull, bsonTypeMinKey, bsonTypeMaxKey:
		return 0, nil
	case bsonTypeObjectID:
		return fixed(12)
	case bsonTypeBool:
		return fixed(1)
	case bsonTypeRegex:
		i := bytes.IndexByte(b, 0)
		if i < 0 {
			return 0, errBSON
		}
		j := bytes.IndexByte(b[i+1:], 0)
		if j < 0 {
			return 0, errBSON
		}
		return i + j + 2, nil
	case bsonTypeDBPointer:
		n, err := str(b)
		if err != nil {
			return 0, err
		}
		return fixed(n + 12)
	case bsonTypeInt32:
		return fixed(4)
	case bsonTypeDecimal:
		return fixed(16)
	}
	return 0, errBSON
}

// first returns the key and value of the first element.
func (d bsonRaw) first() (string, bsonValue, bool) {
	var key string
	var val bsonValue
	found := false
	d.walk(func(k string, v bsonValue) (bool, error) {
		key, val, found = k, v, true
		return false, nil
	})
	return key, val, found
}

// lookup returns the value of the named top-level element.
func (d bsonRaw) lookup(key string) bsonValue {
	var out bsonValue
	d.walk(func(k string, v bsonValue) (bool, error) {
		if k == key {
			out = v
			return false, nil
		}
		return true, nil
	})
	return out
}

// lookupPath descends through nested documents to the named element.
func (d bsonRaw) lookupPath(path ...string) bsonValue {
	var v bsonValue
	for i, key := range path {
		v = d.lookup(key)
		if i == len(path)-1 {
			break
		}
		sub, ok := v.doc()
		if !ok {
			return bsonValue{}
		}
		d = sub
	}
	return v
}

// str returns a string value.
func (v bsonValue) str() (string, bool) {
	if v.typ != bsonTypeString || len(v.data) < 5 {
		return "", false
	}
	return string(v.data[4 : len(v.data)-1]), true
}

// doc returns an embedded document or array value.
func (v bsonValue) doc() (bsonRaw, bool) {
	if v.typ != bsonTypeDocument && v.typ != bsonTypeArray {
		return nil, false
	}
	return bsonRaw(v.data), true
}

// boolean returns a bool value.
func (v bsonValue) boolean() (bool, bool) {
	if v.typ != bsonTypeBool || len(v.data) != 1 {
		return false, false
	}
	return v.data[0] != 0, true
}

// int64 returns an int32, int64 or double value as an integer.
func (v bsonValue) int64() (int64, bool) {
	le := binary.LittleEndian
	switch v.typ {
	case bsonTypeInt32:
		return int64(int32(le.Uint32(v.data))), true
	case bsonTypeInt64:
		return int64(le.Uint64(v.data)), true
	case bsonTypeDouble:
		return int64(math.Float64frombits(le.Uint64(v.data))), true
	}
	return 0, false
}

// bytes returns the payload of a binary value or the text of a string value.
func (v bsonValue) bytes() []byte {
	switch v.typ {
	case bsonTypeBinary:
		return v.data[5:]
	case bsonTypeString:
		s, _ := v.str()
		return []byte(s)
	}
	return nil
}
