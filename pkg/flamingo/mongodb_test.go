package flamingo

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// mongoTestServer spawns a MongoDB collector on a free port and returns the
// address plus a channel that receives captured credential records.
func mongoTestServer(t *testing.T) (string, chan map[string]string, *ConfMongoDB) {
	t.Helper()
	rw := NewRecordWriter()
	got := make(chan map[string]string, 8)
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		got <- rec
		return nil
	})

	conf := NewConfMongoDB()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw

	if err := SpawnMongoDB(conf); err != nil {
		t.Fatalf("SpawnMongoDB failed: %s", err)
	}
	return conf.listener.Addr().String(), got, conf
}

func mongoDial(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %s", err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn
}

// mongoCommand sends a command document as OP_MSG and returns the reply body.
func mongoCommand(t *testing.T, conn net.Conn, d bsonDoc) bsonRaw {
	t.Helper()
	doc := d.marshal()
	le := binary.LittleEndian
	b := make([]byte, 16)
	le.PutUint32(b[4:], 42)
	le.PutUint32(b[12:], mongoOpMsg)
	b = le.AppendUint32(b, 0)
	b = append(b, 0)
	b = append(b, doc...)
	le.PutUint32(b, uint32(len(b)))
	if _, err := conn.Write(b); err != nil {
		t.Fatalf("write: %s", err)
	}

	var hdr [16]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		t.Fatalf("read reply header: %s", err)
	}
	n := int(le.Uint32(hdr[:]))
	if op := le.Uint32(hdr[12:]); op != mongoOpMsg {
		t.Fatalf("reply opcode = %d, want OP_MSG", op)
	}
	if rt := le.Uint32(hdr[8:]); rt != 42 {
		t.Fatalf("responseTo = %d, want 42", rt)
	}
	body := make([]byte, n-16)
	if _, err := io.ReadFull(conn, body); err != nil {
		t.Fatalf("read reply body: %s", err)
	}
	if body[4] != 0 {
		t.Fatalf("reply section kind = %d, want 0", body[4])
	}
	reply, err := bsonParse(body[5:])
	if err != nil {
		t.Fatalf("reply bson: %s", err)
	}
	return reply
}

func mongoWaitCred(t *testing.T, got chan map[string]string) map[string]string {
	t.Helper()
	select {
	case rec := <-got:
		return rec
	case <-time.After(5 * time.Second):
		t.Fatal("no credential captured")
		return nil
	}
}

// mongoTestHello sends a driver-style hello with client metadata.
func mongoTestHello(t *testing.T, conn net.Conn) bsonRaw {
	t.Helper()
	return mongoCommand(t, conn, bsonDoc{
		bsonE("hello", int32(1)),
		bsonE("helloOk", true),
		bsonE("client", bsonDoc{
			bsonE("driver", bsonDoc{bsonE("name", "mongo-go-driver"), bsonE("version", "2.1.0")}),
			bsonE("os", bsonDoc{bsonE("type", "darwin")}),
			bsonE("application", bsonDoc{bsonE("name", "scanner")}),
		}),
		bsonE("$db", "admin"),
	})
}

// TestMongoDBHello verifies the OP_MSG hello reply looks like a writable
// standalone primary.
func TestMongoDBHello(t *testing.T) {
	addr, _, conf := mongoTestServer(t)
	defer conf.Shutdown()

	conn := mongoDial(t, addr)
	defer conn.Close()
	reply := mongoTestHello(t, conn)

	if v, ok := reply.lookup("isWritablePrimary").boolean(); !ok || !v {
		t.Errorf("isWritablePrimary = %v (%v), want true", v, ok)
	}
	if v, ok := reply.lookup("helloOk").boolean(); !ok || !v {
		t.Errorf("helloOk = %v (%v), want true", v, ok)
	}
	if v, _ := reply.lookup("ok").int64(); v != 1 {
		t.Errorf("ok = %d, want 1", v)
	}
	if v, _ := reply.lookup("maxWireVersion").int64(); v != mongoMaxWireVer {
		t.Errorf("maxWireVersion = %d, want %d", v, mongoMaxWireVer)
	}

	// Unauthenticated commands are refused with Unauthorized.
	reply = mongoCommand(t, conn, bsonDoc{bsonE("find", "users"), bsonE("$db", "admin")})
	if code, _ := reply.lookup("code").int64(); code != 13 {
		t.Errorf("find code = %d, want 13", code)
	}
}

// TestMongoDBSaslPlain verifies a PLAIN saslStart yields the cleartext
// credential together with the driver metadata from hello.
func TestMongoDBSaslPlain(t *testing.T) {
	addr, got, conf := mongoTestServer(t)
	defer conf.Shutdown()

	conn := mongoDial(t, addr)
	defer conn.Close()
	mongoTestHello(t, conn)

	reply := mongoCommand(t, conn, bsonDoc{
		bsonE("saslStart", int32(1)),
		bsonE("mechanism", "PLAIN"),
		bsonE("payload", bsonBinary("\x00ldapuser\x00hunter2")),
		bsonE("autoAuthorize", int32(1)),
		bsonE("$db", "$external"),
	})
	if code, _ := reply.lookup("code").int64(); code != 18 {
		t.Errorf("saslStart code = %d, want 18", code)
	}

	rec := mongoWaitCred(t, got)
	if rec["_proto"] != "mongodb" {
		t.Errorf("_proto = %q, want mongodb", rec["_proto"])
	}
	if rec["username"] != "ldapuser" || rec["password"] != "hunter2" {
		t.Errorf("PLAIN captured %q/%q, want ldapuser/hunter2", rec["username"], rec["password"])
	}
	if rec["method"] != "PLAIN" {
		t.Errorf("method = %q, want PLAIN", rec["method"])
	}
	for k, want := range map[string]string{
		"driver":           "mongo-go-driver",
		"driver_version":   "2.1.0",
		"application_name": "scanner",
		"os":               "darwin",
	} {
		if rec[k] != want {
			t.Errorf("%s = %q, want %q", k, rec[k], want)
		}
	}
}

// scramSHA256Proof computes the SCRAM-SHA-256 client proof for a password
// and AuthMessage with the given salt and iteration count.
func scramSHA256Proof(t *testing.T, password string, salt []byte, iter int, authMsg string) []byte {
	t.Helper()
	salted, err := pbkdf2.Key(sha256.New, password, salt, iter, sha256.Size)
	if err != nil {
		t.Fatalf("pbkdf2: %s", err)
	}
	mac := func(key []byte, msg string) []byte {
		m := hmac.New(sha256.New, key)
		m.Write([]byte(msg))
		return m.Sum(nil)
	}
	clientKey := mac(salted, "Client Key")
	storedKey := sha256.Sum256(clientKey)
	proof := mac(storedKey[:], authMsg)
	for i := range proof {
		proof[i] ^= clientKey[i]
	}
	return proof
}

// TestMongoDBScramSHA256 runs a real SCRAM-SHA-256 conversation and checks
// the recorded material reproduces the client proof offline.
func TestMongoDBScramSHA256(t *testing.T) {
	const user, password, clientNonce = "scramuser", "correct horse", "rOprNGfwEbeRWgbNEkqO"

	addr, got, conf := mongoTestServer(t)
	defer conf.Shutdown()

	conn := mongoDial(t, addr)
	defer conn.Close()
	mongoTestHello(t, conn)

	clientFirstBare := "n=" + user + ",r=" + clientNonce
	reply := mongoCommand(t, conn, bsonDoc{
		bsonE("saslStart", int32(1)),
		bsonE("mechanism", "SCRAM-SHA-256"),
		bsonE("payload", bsonBinary("n,,"+clientFirstBare)),
		bsonE("options", bsonDoc{bsonE("skipEmptyExchange", true)}),
		bsonE("$db", "admin"),
	})
	if v, _ := reply.lookup("ok").int64(); v != 1 {
		t.Fatalf("saslStart failed: %x", []byte(reply))
	}
	convID, _ := reply.lookup("conversationId").int64()
	serverFirst := string(reply.lookup("payload").bytes())

	attrs := mongoScramAttrs(serverFirst)
	if !strings.HasPrefix(attrs["r"], clientNonce) {
		t.Fatalf("server nonce %q does not extend client nonce", attrs["r"])
	}
	salt, err := base64.StdEncoding.DecodeString(attrs["s"])
	if err != nil {
		t.Fatalf("salt: %s", err)
	}
	iter, _ := strconv.Atoi(attrs["i"])
	if iter != mongoScramIterSHA2 {
		t.Errorf("iterations = %d, want %d", iter, mongoScramIterSHA2)
	}

	clientFinalNoProof := "c=biws,r=" + attrs["r"]
	authMsg := clientFirstBare + "," + serverFirst + "," + clientFinalNoProof
	proof := scramSHA256Proof(t, password, salt, iter, authMsg)
	proofB64 := base64.StdEncoding.EncodeToString(proof)

	reply = mongoCommand(t, conn, bsonDoc{
		bsonE("saslContinue", int32(1)),
		bsonE("conversationId", int32(convID)),
		bsonE("payload", bsonBinary(clientFinalNoProof+",p="+proofB64)),
		bsonE("$db", "admin"),
	})
	if code, _ := reply.lookup("code").int64(); code != 18 {
		t.Errorf("saslContinue code = %d, want 18", code)
	}

	rec := mongoWaitCred(t, got)
	if rec["username"] != user || rec["method"] != "SCRAM-SHA-256" {
		t.Errorf("captured %q via %q, want %s via SCRAM-SHA-256", rec["username"], rec["method"], user)
	}
	if rec["client_nonce"] != clientNonce || rec["server_nonce"] != attrs["r"] {
		t.Errorf("nonces = %q/%q, want %q/%q", rec["client_nonce"], rec["server_nonce"], clientNonce, attrs["r"])
	}
	if rec["salt"] != attrs["s"] || rec["iterations"] != attrs["i"] {
		t.Errorf("salt/iterations = %q/%q, want %q/%q", rec["salt"], rec["iterations"], attrs["s"], attrs["i"])
	}
	if rec["auth_message"] != authMsg {
		t.Errorf("auth_message = %q, want %q", rec["auth_message"], authMsg)
	}
	if rec["client_proof"] != proofB64 {
		t.Errorf("client_proof = %q, want %q", rec["client_proof"], proofB64)
	}
	if rec["channel_binding"] != "biws" {
		t.Errorf("channel_binding = %q, want biws", rec["channel_binding"])
	}

	// Offline check: the recorded fields alone, plus the known password,
	// must reproduce the recorded proof.
	recSalt, _ := base64.StdEncoding.DecodeString(rec["salt"])
	recIter, _ := strconv.Atoi(rec["iterations"])
	recomputed := base64.StdEncoding.EncodeToString(
		scramSHA256Proof(t, password, recSalt, recIter, rec["auth_message"]))
	if recomputed != rec["client_proof"] {
		t.Errorf("offline proof %q != recorded %q", recomputed, rec["client_proof"])
	}
	wrong := base64.StdEncoding.EncodeToString(
		scramSHA256Proof(t, "wrong password", recSalt, recIter, rec["auth_message"]))
	if wrong == rec["client_proof"] {
		t.Error("wrong password reproduced the proof")
	}
}
