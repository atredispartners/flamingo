package ldap

import (
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"
)

//
func TestAdd(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", modifyTestHandler{})
		s.AddFunc("", modifyTestHandler{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()
	go func() {
		cmd := exec.Command("ldapadd", "-v", "-H", ldapURL, "-x", "-f", "tests/add.ldif")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "modify complete") {
			t.Errorf("ldapadd failed: %v", string(out))
		}
		cmd = exec.Command("ldapadd", "-v", "-H", ldapURL, "-x", "-f", "tests/add2.ldif")
		out, _ = cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_add: Insufficient access") {
			t.Errorf("ldapadd should have failed: %v", string(out))
		}
		if strings.Contains(string(out), "modify complete") {
			t.Errorf("ldapadd should have failed: %v", string(out))
		}
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapadd command timed out")
	}
	quit <- true
}

//
func TestDelete(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", modifyTestHandler{})
		s.DeleteFunc("", modifyTestHandler{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()
	go func() {
		cmd := exec.Command("ldapdelete", "-v", "-H", ldapURL, "-x", "cn=Delete Me,dc=example,dc=com")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "Delete Result: Success (0)") || !strings.Contains(string(out), "Additional info: Success") {
			t.Errorf("ldapdelete failed: %v", string(out))
		}
		cmd = exec.Command("ldapdelete", "-v", "-H", ldapURL, "-x", "cn=Bob,dc=example,dc=com")
		out, _ = cmd.CombinedOutput()
		if strings.Contains(string(out), "Success") || !strings.Contains(string(out), "ldap_delete: Insufficient access") {
			t.Errorf("ldapdelete should have failed: %v", string(out))
		}
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapdelete command timed out")
	}
	quit <- true
}

func TestModify(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", modifyTestHandler{})
		s.ModifyFunc("", modifyTestHandler{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()
	go func() {
		cmd := exec.Command("ldapmodify", "-v", "-H", ldapURL, "-x", "-f", "tests/modify.ldif")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "modify complete") {
			t.Errorf("ldapmodify failed: %v", string(out))
		}
		cmd = exec.Command("ldapmodify", "-v", "-H", ldapURL, "-x", "-f", "tests/modify2.ldif")
		out, _ = cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_modify: Insufficient access") || strings.Contains(string(out), "modify complete") {
			t.Errorf("ldapmodify should have failed: %v", string(out))
		}
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapadd command timed out")
	}
	quit <- true
}

/*
func TestModifyDN(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", modifyTestHandler{})
		s.AddFunc("", modifyTestHandler{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()
	go func() {
		cmd := exec.Command("ldapadd", "-v", "-H", ldapURL, "-x", "-f", "tests/add.ldif")
		//ldapmodrdn -H ldap://localhost:3389 -x "uid=babs,dc=example,dc=com" "uid=babsy,dc=example,dc=com"
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "modify complete") {
			t.Errorf("ldapadd failed: %v", string(out))
		}
		cmd = exec.Command("ldapadd", "-v", "-H", ldapURL, "-x", "-f", "tests/add2.ldif")
		out, _ = cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_add: Insufficient access") {
			t.Errorf("ldapadd should have failed: %v", string(out))
		}
		if strings.Contains(string(out), "modify complete") {
			t.Errorf("ldapadd should have failed: %v", string(out))
		}
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapadd command timed out")
	}
	quit <- true
}
*/

//
type modifyTestHandler struct {
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
	return LDAPResultInsufficientAccessRights, nil
}
