package ldap

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"

	ber "github.com/atredispartners/flamingo/pkg/asn1-ber"
)

// The client half of this package implements Modify but not Add, Delete or
// ModifyDN, so the three helpers below encode those requests directly. They
// send what the ldapadd/ldapdelete/ldapmodrdn invocations these tests used to
// shell out to would have sent.

// sendRequest writes one request operation on l and returns the result code of
// the response, failing if the server answered with a different operation.
func sendRequest(l *Conn, request *ber.Packet, responseTag uint8) (LDAPResultCode, error) {
	messageID := l.nextMessageID()

	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "MessageID"))
	packet.AppendChild(request)

	channel, err := l.sendMessage(packet)
	if err != nil {
		return 0, err
	}
	defer l.finishMessage(messageID)

	response := <-channel
	if response == nil {
		return 0, errors.New("ldap: could not retrieve response")
	}
	if len(response.Children) < 2 || response.Children[1].Tag != responseTag {
		return 0, fmt.Errorf("ldap: unexpected response operation %d", response.Children[1].Tag)
	}

	code, _ := getLDAPResultCode(response)
	return code, nil
}

// clientAdd sends an AddRequest for the given DN and attributes.
func clientAdd(l *Conn, dn string, attributes []Attribute) (LDAPResultCode, error) {
	request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationAddRequest, nil, "Add Request")
	request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "Entry"))

	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	for _, a := range attributes {
		attr := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attribute")
		attr.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, a.attrType, "Type"))
		vals := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "Values")
		for _, v := range a.attrVals {
			vals.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "Value"))
		}
		attr.AppendChild(vals)
		attrs.AppendChild(attr)
	}
	request.AppendChild(attrs)

	return sendRequest(l, request, ApplicationAddResponse)
}

// clientDelete sends a DelRequest, whose body is the bare DN rather than a
// sequence.
func clientDelete(l *Conn, dn string) (LDAPResultCode, error) {
	request := ber.NewString(ber.ClassApplication, ber.TypePrimitive, ApplicationDelRequest, dn, "Del Request")
	return sendRequest(l, request, ApplicationDelResponse)
}

// clientModifyDN sends a ModifyDNRequest without a newSuperior.
func clientModifyDN(l *Conn, dn, newRDN string, deleteOldRDN bool) (LDAPResultCode, error) {
	request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationModifyDNRequest, nil, "Modify DN Request")
	request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "Entry"))
	request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, newRDN, "New RDN"))
	request.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, deleteOldRDN, "Delete Old RDN"))
	return sendRequest(l, request, ApplicationModifyDNResponse)
}

// testModifyClient starts a server whose bind and modify operations are
// handled by h and returns an anonymously bound client. register attaches h to
// whichever operation the test is about, so no other operation is reachable.
func testModifyClient(t *testing.T, h modifyTestHandler, register func(s *Server, h modifyTestHandler)) *Conn {
	t.Helper()

	s := NewServer()
	s.BindFunc("", h)
	register(s, h)

	l := dialTest(t, testServer(t, s))
	if err := l.Bind("", ""); err != nil {
		t.Fatalf("bind failed: %s", err)
	}
	return l
}

// addLDIF is the entry tests/add.ldif describes, which modifyTestHandler
// accepts; addLDIF2 is tests/add2.ldif, which it refuses.
var addLDIF = []Attribute{
	{attrType: "objectClass", attrVals: []string{"person"}},
	{attrType: "cn", attrVals: []string{"Barbara Jensen"}},
	{attrType: "sn", attrVals: []string{"Jensen"}},
	{attrType: "mail", attrVals: []string{"bjensen@example.com"}},
	{attrType: "uid", attrVals: []string{"bjensen"}},
}

var addLDIF2 = []Attribute{
	{attrType: "objectClass", attrVals: []string{"person"}},
	{attrType: "cn", attrVals: []string{"Big Bob"}},
	{attrType: "sn", attrVals: []string{"Bob"}},
	{attrType: "mail", attrVals: []string{"bob@example.com"}},
	{attrType: "uid", attrVals: []string{"bob"}},
}

func TestAdd(t *testing.T) {
	l := testModifyClient(t, modifyTestHandler{}, func(s *Server, h modifyTestHandler) { s.AddFunc("", h) })

	code, err := clientAdd(l, "cn=Barbara Jensen,dc=example,dc=com", addLDIF)
	if err != nil {
		t.Fatalf("add failed: %s", err)
	}
	if code != LDAPResultSuccess {
		t.Errorf("add returned %d, want success", code)
	}

	code, err = clientAdd(l, "cn=Big Bob,dc=example,dc=com", addLDIF2)
	if err != nil {
		t.Fatalf("add failed: %s", err)
	}
	if code != LDAPResultInsufficientAccessRights {
		t.Errorf("add of an unexpected entry returned %d, want insufficient access", code)
	}
}

func TestDelete(t *testing.T) {
	l := testModifyClient(t, modifyTestHandler{}, func(s *Server, h modifyTestHandler) { s.DeleteFunc("", h) })

	code, err := clientDelete(l, "cn=Delete Me,dc=example,dc=com")
	if err != nil {
		t.Fatalf("delete failed: %s", err)
	}
	if code != LDAPResultSuccess {
		t.Errorf("delete returned %d, want success", code)
	}

	code, err = clientDelete(l, "cn=Bob,dc=example,dc=com")
	if err != nil {
		t.Fatalf("delete failed: %s", err)
	}
	if code != LDAPResultInsufficientAccessRights {
		t.Errorf("delete of an unexpected DN returned %d, want insufficient access", code)
	}
}

func TestModify(t *testing.T) {
	l := testModifyClient(t, modifyTestHandler{}, func(s *Server, h modifyTestHandler) { s.ModifyFunc("", h) })

	// The changes tests/modify.ldif asks for. A delete with no values
	// removes the whole attribute, which is the case modifyTestHandler
	// checks for on "details".
	req := NewModifyRequest("cn=testy,dc=example,dc=com")
	req.Replace("mail", []string{"modme@example.com"})
	req.Delete("manager", nil)
	req.Add("title", []string{"Grand Poobah"})
	req.Delete("description", nil)
	req.Delete("details", nil)
	req.Replace("fullname", []string{"Test Testerson"})
	if err := l.Modify(req); err != nil {
		t.Errorf("modify failed: %s", err)
	}

	// tests/modify2.ldif, which the handler refuses.
	req = NewModifyRequest("cn=testo,dc=example,dc=com")
	req.Replace("mail", []string{"modid@example.com"})
	req.Delete("manager", nil)
	req.Add("title", []string{"Other Poobah"})
	err := l.Modify(req)
	if err == nil {
		t.Fatal("modify of an unexpected entry succeeded")
	}
	if code := resultCode(t, err); code != LDAPResultInsufficientAccessRights {
		t.Errorf("modify of an unexpected entry returned %d, want insufficient access", code)
	}
}

func TestModifyDN(t *testing.T) {
	recorder := &modifyDNRecorder{}
	l := testModifyClient(t, modifyTestHandler{modifyDN: recorder}, func(s *Server, h modifyTestHandler) { s.ModifyDNFunc("", h) })

	code, err := clientModifyDN(l, "uid=babs,dc=example,dc=com", "uid=babsy", true)
	if err != nil {
		t.Fatalf("modify DN failed: %s", err)
	}
	if code != LDAPResultInsufficientAccessRights {
		t.Errorf("modify DN returned %d, want insufficient access", code)
	}

	got, calls := recorder.last()
	if calls != 1 {
		t.Fatalf("expected 1 modify DN to reach the handler, got %d", calls)
	}
	if got.dn != "uid=babs,dc=example,dc=com" || got.newrdn != "uid=babsy" || !got.deleteoldrdn {
		t.Errorf("handler saw %+v, want the request as sent", got)
	}
}

// modifyDNRecorder remembers the ModifyDN requests a handler was given, so a
// test can assert on what the server parsed out of the wire format.
type modifyDNRecorder struct {
	mu       sync.Mutex
	request  ModifyDNRequest
	requests int
}

func (r *modifyDNRecorder) record(req ModifyDNRequest) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.request = req
	r.requests++
}

func (r *modifyDNRecorder) last() (ModifyDNRequest, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.request, r.requests
}

type modifyTestHandler struct {
	// modifyDN, when set, records every ModifyDN request the handler sees.
	modifyDN *modifyDNRecorder
}

func (h modifyTestHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (LDAPResultCode, error) {
	if bindDN == "" && bindSimplePw == "" {
		return LDAPResultSuccess, nil
	}
	return LDAPResultInvalidCredentials, nil
}
func (h modifyTestHandler) Add(boundDN string, req AddRequest, conn net.Conn) (LDAPResultCode, error) {
	// only succeed on expected contents of add.ldif:
	if len(req.attributes) == 5 && req.dn == "cn=Barbara Jensen,dc=example,dc=com" &&
		req.attributes[2].attrType == "sn" && len(req.attributes[2].attrVals) == 1 &&
		req.attributes[2].attrVals[0] == "Jensen" {
		return LDAPResultSuccess, nil
	}
	return LDAPResultInsufficientAccessRights, nil
}
func (h modifyTestHandler) Delete(boundDN, deleteDN string, conn net.Conn) (LDAPResultCode, error) {
	// only succeed on expected deleteDN
	if deleteDN == "cn=Delete Me,dc=example,dc=com" {
		return LDAPResultSuccess, nil
	}
	return LDAPResultInsufficientAccessRights, nil
}
func (h modifyTestHandler) Modify(boundDN string, req ModifyRequest, conn net.Conn) (LDAPResultCode, error) {
	// only succeed on expected contents of modify.ldif:
	if req.Dn == "cn=testy,dc=example,dc=com" && len(req.AddAttributes) == 1 &&
		len(req.DeleteAttributes) == 3 && len(req.ReplaceAttributes) == 2 &&
		req.DeleteAttributes[2].AttrType == "details" && len(req.DeleteAttributes[2].AttrVals) == 0 {
		return LDAPResultSuccess, nil
	}
	return LDAPResultInsufficientAccessRights, nil
}
func (h modifyTestHandler) ModifyDN(boundDN string, req ModifyDNRequest, conn net.Conn) (LDAPResultCode, error) {
	if h.modifyDN != nil {
		h.modifyDN.record(req)
	}
	return LDAPResultInsufficientAccessRights, nil
}
