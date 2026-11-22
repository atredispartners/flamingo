package ldap

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"sync"
	"testing"

	log "github.com/sirupsen/logrus"
)

const serverBaseDN = "o=testers,c=test"

// testServer starts s on a kernel-assigned loopback port and returns the
// address to dial. Port 0 keeps tests from colliding with each other or with
// anything else on the machine, and the listener is open by the time this
// returns, so a client may connect immediately - the kernel queues the
// connection until Serve accepts it.
func testServer(t *testing.T, s *Server) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %s", err)
	}
	return serveTest(t, s, ln)
}

// testServerTLS is testServer over an LDAPS listener. Server.ListenAndServeTLS
// cannot be used here because it takes an address rather than a listener, so
// the port it ends up on is not observable.
func testServerTLS(t *testing.T, s *Server, certFile, keyFile string) string {
	t.Helper()

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("load keypair: %s", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("tls listen: %s", err)
	}
	return serveTest(t, s, ln)
}

// serveTest runs s.Serve(ln) in the background and shuts it down when the test
// ends. Serve reports its error over a channel rather than calling t.Errorf
// from the goroutine: an assertion that lands after the test function has
// returned panics the whole test binary.
func serveTest(t *testing.T, s *Server, ln net.Listener) string {
	t.Helper()

	quit := make(chan bool)
	s.QuitChannel(quit)

	served := make(chan error, 1)
	go func() { served <- s.Serve(ln) }()

	t.Cleanup(func() {
		// Quit is unbuffered, so a send would block forever if Serve had
		// already returned on its own.
		select {
		case quit <- true:
		case err := <-served:
			if err != nil {
				t.Errorf("Serve returned early: %s", err)
			}
			return
		}
		if err := <-served; err != nil {
			t.Errorf("Serve: %s", err)
		}
	})

	return ln.Addr().String()
}

// dialTest connects this package's own client to addr and closes it when the
// test ends. Cleanups run last-registered-first, so the client is always torn
// down before the server it is talking to.
func dialTest(t *testing.T, addr string) *Conn {
	t.Helper()

	l, err := Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial(%s): %s", addr, err)
	}
	t.Cleanup(l.Close)
	return l
}

// resultCode reports the LDAP result code an error from the client carries.
// Every client operation wraps a non-success result in *Error, so anything
// else is a failure in its own right.
func resultCode(t *testing.T, err error) LDAPResultCode {
	t.Helper()

	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("expected *ldap.Error, got %T: %v", err, err)
	}
	return e.ResultCode
}

// searchAll runs a subtree search for every entry and every attribute, which
// is what most of these tests want from the server. The filter is the one
// ldapsearch defaults to, since the client's CompileFilter rejects an empty
// one outright.
func searchAll(t *testing.T, l *Conn, baseDN string) *SearchResult {
	t.Helper()

	res, err := l.Search(NewSearchRequest(baseDN, ScopeWholeSubtree, NeverDerefAliases, 0, 0, false, "(objectclass=*)", nil, nil))
	if err != nil {
		t.Fatalf("search %q: %s", baseDN, err)
	}
	return res
}

// entryDNs returns the DNs of a search result in the order they arrived.
func entryDNs(res *SearchResult) []string {
	dns := make([]string, 0, len(res.Entries))
	for _, e := range res.Entries {
		dns = append(dns, e.DN)
	}
	return dns
}

// ///////////////////////
func TestBindAnonOK(t *testing.T) {
	s := NewServer()
	s.BindFunc("", bindAnonOK{})

	l := dialTest(t, testServer(t, s))
	if err := l.Bind("", ""); err != nil {
		t.Errorf("anonymous bind failed: %s", err)
	}
}

// ///////////////////////
func TestBindAnonFail(t *testing.T) {
	// No BindFunc is registered, so the server's default handler answers,
	// and it refuses every bind.
	s := NewServer()

	l := dialTest(t, testServer(t, s))
	err := l.Bind("", "")
	if err == nil {
		t.Fatal("anonymous bind succeeded against the default handler")
	}
	if code := resultCode(t, err); code != LDAPResultInvalidCredentials {
		t.Errorf("expected invalid credentials, got %d", code)
	}
}

// ///////////////////////
func TestBindSimpleOK(t *testing.T) {
	s := NewServer()
	s.SearchFunc("", searchSimple{})
	s.BindFunc("", bindSimple{})

	l := dialTest(t, testServer(t, s))
	if err := l.Bind("cn=testy,"+serverBaseDN, "iLike2test"); err != nil {
		t.Fatalf("bind failed: %s", err)
	}
	if res := searchAll(t, l, serverBaseDN); len(res.Entries) != 3 {
		t.Errorf("expected 3 entries, got %d: %v", len(res.Entries), entryDNs(res))
	}
}

// ///////////////////////
func TestBindSimpleFailBadPw(t *testing.T) {
	s := NewServer()
	s.BindFunc("", bindSimple{})

	l := dialTest(t, testServer(t, s))
	err := l.Bind("cn=testy,"+serverBaseDN, "BADPassword")
	if err == nil {
		t.Fatal("bind with a bad password succeeded")
	}
	if code := resultCode(t, err); code != LDAPResultInvalidCredentials {
		t.Errorf("expected invalid credentials, got %d", code)
	}
}

// ///////////////////////
func TestBindSimpleFailBadDn(t *testing.T) {
	s := NewServer()
	s.BindFunc("", bindSimple{})

	l := dialTest(t, testServer(t, s))
	err := l.Bind("cn=testoy,"+serverBaseDN, "iLike2test")
	if err == nil {
		t.Fatal("bind with a bad DN succeeded")
	}
	if code := resultCode(t, err); code != LDAPResultInvalidCredentials {
		t.Errorf("expected invalid credentials, got %d", code)
	}
}

// ///////////////////////
// TestBindSimpleEmptyPassword is a regression test for the BER decoder
// discarding zero-length elements. A simple bind with an empty password ends
// in the two bytes 0x80 0x00, and rejecting that element threw away the entire
// bind request, so the handler never saw the attempt at all - which is exactly
// the attempt flamingo wants to record.
func TestBindSimpleEmptyPassword(t *testing.T) {
	binder := &recordingBinder{result: LDAPResultInvalidCredentials}
	s := NewServer()
	s.BindFunc("", binder)

	l := dialTest(t, testServer(t, s))
	bindDN := "cn=testy," + serverBaseDN
	err := l.Bind(bindDN, "")
	if err == nil {
		t.Fatal("bind with an empty password succeeded")
	}
	if code := resultCode(t, err); code != LDAPResultInvalidCredentials {
		t.Fatalf("expected invalid credentials, got %d", code)
	}

	binds := binder.binds()
	if len(binds) != 1 {
		t.Fatalf("expected 1 bind to reach the handler, got %d", len(binds))
	}
	if binds[0].dn != bindDN {
		t.Errorf("handler saw bind DN %q, want %q", binds[0].dn, bindDN)
	}
	if binds[0].pw != "" {
		t.Errorf("handler saw password %q, want empty", binds[0].pw)
	}
}

// ///////////////////////
func TestBindSSL(t *testing.T) {
	s := NewServer()
	s.BindFunc("", bindAnonOK{})
	addr := testServerTLS(t, s, "tests/cert_DONOTUSE.pem", "tests/key_DONOTUSE.pem")

	// The checked-in test certificate is self-signed and expired in 2015.
	// This test is about the server speaking LDAPS, not about what a client
	// makes of the chain, so verification is skipped rather than pinned to
	// a fixture that has to be regenerated.
	l, err := DialTLS("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("DialTLS(%s): %s", addr, err)
	}
	defer l.Close()

	if err := l.Bind("", ""); err != nil {
		t.Errorf("anonymous bind over TLS failed: %s", err)
	}
}

// ///////////////////////
// TestListenAndServeTLSBadCert covers the one branch testServerTLS does not
// reach: ListenAndServeTLS must report a keypair it cannot load instead of
// starting a listener.
func TestListenAndServeTLSBadCert(t *testing.T) {
	s := NewServer()
	if err := s.ListenAndServeTLS("127.0.0.1:0", "tests/nonexistent.pem", "tests/nonexistent.key"); err == nil {
		t.Error("ListenAndServeTLS accepted a missing keypair")
	}
}

// ///////////////////////
func TestBindPanic(t *testing.T) {
	s := NewServer()
	s.BindFunc("", bindPanic{})

	l := dialTest(t, testServer(t, s))
	err := l.Bind("", "")
	if err == nil {
		t.Fatal("bind succeeded although the handler panicked")
	}
	if code := resultCode(t, err); code != LDAPResultOperationsError {
		t.Errorf("expected operations error after handler panic, got %d", code)
	}
}

// ///////////////////////
// testStatsWriter collects log output so a stats failure can report what the
// server logged. The server logs from its own goroutines, so the buffer needs
// a lock of its own.
type testStatsWriter struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (tsw *testStatsWriter) Write(buf []byte) (int, error) {
	tsw.mu.Lock()
	defer tsw.mu.Unlock()
	return tsw.buffer.Write(buf)
}

func (tsw *testStatsWriter) String() string {
	tsw.mu.Lock()
	defer tsw.mu.Unlock()
	return tsw.buffer.String()
}

func TestSearchStats(t *testing.T) {
	w := &testStatsWriter{}
	log.SetOutput(w)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	s := NewServer()
	s.SearchFunc("", searchSimple{})
	s.BindFunc("", bindAnonOK{})
	s.SetStats(true)

	l := dialTest(t, testServer(t, s))
	if err := l.Bind("", ""); err != nil {
		t.Fatalf("bind failed: %s", err)
	}
	searchAll(t, l, serverBaseDN)

	// The search response has been read, so the server has already counted
	// the connection, the bind and the search.
	stats := s.GetStats()
	if stats.Conns != 1 || stats.Binds != 1 || stats.Searches != 1 {
		t.Errorf("stats data missing or incorrect: %+v, log: %s", stats, w.String())
	}
}

// ///////////////////////
type bindAnonOK struct {
}

func (b bindAnonOK) Bind(bindDN, bindSimplePw string, conn net.Conn) (LDAPResultCode, error) {
	if bindDN == "" && bindSimplePw == "" {
		return LDAPResultSuccess, nil
	}
	return LDAPResultInvalidCredentials, nil
}

type bindSimple struct {
}

func (b bindSimple) Bind(bindDN, bindSimplePw string, conn net.Conn) (LDAPResultCode, error) {
	if bindDN == "cn=testy,o=testers,c=test" && bindSimplePw == "iLike2test" {
		return LDAPResultSuccess, nil
	}
	return LDAPResultInvalidCredentials, nil
}

type bindSimple2 struct {
}

func (b bindSimple2) Bind(bindDN, bindSimplePw string, conn net.Conn) (LDAPResultCode, error) {
	if bindDN == "cn=testy,o=testers,c=testz" && bindSimplePw == "ZLike2test" {
		return LDAPResultSuccess, nil
	}
	return LDAPResultInvalidCredentials, nil
}

type bindPanic struct {
}

func (b bindPanic) Bind(bindDN, bindSimplePw string, conn net.Conn) (LDAPResultCode, error) {
	panic("test panic at the disco")
}

// simpleBind is one call recorded by recordingBinder.
type simpleBind struct {
	dn string
	pw string
}

// recordingBinder answers every bind with a fixed result and remembers what it
// was asked, so a test can assert on what actually reached the handler.
type recordingBinder struct {
	result LDAPResultCode

	mu       sync.Mutex
	recorded []simpleBind
}

func (b *recordingBinder) Bind(bindDN, bindSimplePw string, conn net.Conn) (LDAPResultCode, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.recorded = append(b.recorded, simpleBind{dn: bindDN, pw: bindSimplePw})
	return b.result, nil
}

func (b *recordingBinder) binds() []simpleBind {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]simpleBind(nil), b.recorded...)
}

type searchSimple struct {
}

func (s searchSimple) Search(boundDN string, searchReq SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	entries := []*Entry{
		{"cn=ned,o=testers,c=test", []*EntryAttribute{
			{"cn", []string{"ned"}},
			{"o", []string{"ate"}},
			{"uidNumber", []string{"5000"}},
			{"accountstatus", []string{"active"}},
			{"uid", []string{"ned"}},
			{"description", []string{"ned via sa"}},
			{"objectclass", []string{"posixaccount"}},
		}},
		{"cn=trent,o=testers,c=test", []*EntryAttribute{
			{"cn", []string{"trent"}},
			{"o", []string{"ate"}},
			{"uidNumber", []string{"5005"}},
			{"accountstatus", []string{"active"}},
			{"uid", []string{"trent"}},
			{"description", []string{"trent via sa"}},
			{"objectclass", []string{"posixaccount"}},
		}},
		{"cn=randy,o=testers,c=test", []*EntryAttribute{
			{"cn", []string{"randy"}},
			{"o", []string{"ate"}},
			{"uidNumber", []string{"5555"}},
			{"accountstatus", []string{"active"}},
			{"uid", []string{"randy"}},
			{"objectclass", []string{"posixaccount"}},
		}},
	}
	return ServerSearchResult{entries, []string{}, []Control{}, LDAPResultSuccess}, nil
}

type searchSimple2 struct {
}

func (s searchSimple2) Search(boundDN string, searchReq SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	entries := []*Entry{
		{"cn=hamburger,o=testers,c=testz", []*EntryAttribute{
			{"cn", []string{"hamburger"}},
			{"o", []string{"testers"}},
			{"uidNumber", []string{"5000"}},
			{"accountstatus", []string{"active"}},
			{"uid", []string{"hamburger"}},
			{"objectclass", []string{"posixaccount"}},
		}},
	}
	return ServerSearchResult{entries, []string{}, []Control{}, LDAPResultSuccess}, nil
}

type searchPanic struct {
}

func (s searchPanic) Search(boundDN string, searchReq SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	panic("this is a test panic")
}

type searchControls struct {
}

func (s searchControls) Search(boundDN string, searchReq SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	entries := []*Entry{}
	if len(searchReq.Controls) == 1 && searchReq.Controls[0].GetControlType() == "1.2.3.4.5" {
		newEntry := &Entry{"cn=hamburger,o=testers,c=testz", []*EntryAttribute{
			{"cn", []string{"hamburger"}},
			{"o", []string{"testers"}},
			{"uidNumber", []string{"5000"}},
			{"accountstatus", []string{"active"}},
			{"uid", []string{"hamburger"}},
			{"objectclass", []string{"posixaccount"}},
		}}
		entries = append(entries, newEntry)
	}
	return ServerSearchResult{entries, []string{}, []Control{}, LDAPResultSuccess}, nil
}
