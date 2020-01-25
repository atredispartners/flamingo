// +build ignore

package main

import (
	"crypto/sha256"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/nmcclain/ldap"
)

type ldapHandler struct {
	sessions   map[string]session
	lock       sync.Mutex
	ldapServer string
	ldapPort   int
}

///////////// Run a simple LDAP proxy
func main() {
	s := ldap.NewServer()

	handler := ldapHandler{
		sessions:   make(map[string]session),
		ldapServer: "localhost",
		ldapPort:   3389,
	}
	s.BindFunc("", handler)
	s.SearchFunc("", handler)
	s.CloseFunc("", handler)

	// start the server
	if err := s.ListenAndServe("localhost:3388"); err != nil {
		log.Fatal("LDAP Server Failed: %s", err.Error())
	}
}

/////////////
type session struct {
	id   string
	c    net.Conn
	ldap *ldap.Conn
}

func (h ldapHandler) getSession(conn net.Conn) (session, error) {
	id := connID(conn)
	h.lock.Lock()
	s, ok := h.sessions[id] // use server connection if it exists
	h.lock.Unlock()
	if !ok { // open a new server connection if not
		l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", h.ldapServer, h.ldapPort))
		if err != nil {
			return session{}, err
		}
		s = session{id: id, c: conn, ldap: l}
		h.lock.Lock()
		h.sessions[s.id] = s
		h.lock.Unlock()
	}
	return s, nil
}

/////////////
func (h ldapHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldap.LDAPResultCode, error) {
	s, err := h.getSession(conn)
	if err != nil {
		return ldap.LDAPResultOperationsError, err
	}
	if err := s.ldap.Bind(bindDN, bindSimplePw); err != nil {
		return ldap.LDAPResultOperationsError, err
	}
	return ldap.LDAPResultSuccess, nil
}

/////////////
func (h ldapHandler) Search(boundDN string, searchReq ldap.SearchRequest, conn net.Conn) (ldap.ServerSearchResult, error) {
	s, err := h.getSession(conn)
	if err != nil {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, nil
	}
	search := ldap.NewSearchRequest(
		searchReq.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		searchReq.Filter,
		searchReq.Attributes,
		nil)
	sr, err := s.ldap.Search(search)
	if err != nil {
		return ldap.ServerSearchResult{}, err
	}
	//log.Printf("P: Search OK: %s -> num of entries = %d\n", search.Filter, len(sr.Entries))
	return ldap.ServerSearchResult{sr.Entries, []string{}, []ldap.Control{}, ldap.LDAPResultSuccess}, nil
}
func (h ldapHandler) Close(boundDN string, conn net.Conn) error {
	conn.Close() // close connection to the server when then client is closed
	h.lock.Lock()
	defer h.lock.Unlock()
	delete(h.sessions, connID(conn))
	return nil
}
func connID(conn net.Conn) string {
	h := sha256.New()
	h.Write([]byte(conn.LocalAddr().String() + conn.RemoteAddr().String()))
	sha := fmt.Sprintf("% x", h.Sum(nil))
	return string(sha)
}
