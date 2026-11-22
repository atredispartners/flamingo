package ldap

import (
	"testing"
)

// These used to run against ldap.itd.umich.edu, a public server that has been
// gone for years. They now exercise the same client calls against this
// package's own server, which is what made them repeatable.

var clientTestFilters = []string{
	"(cn=ned)",
	"(&(objectclass=posixaccount)(description=*))",
	"(|(uid=ned)(uid=trent))",
}

// clientTestEntries is how many entries searchSimple{} has for each of the
// filters above, with the server enforcing them.
var clientTestEntries = []int{1, 2, 2}

var clientTestAttributes = []string{"cn", "description"}

// testClientServer starts a filter-enforcing server over searchSimple{} and
// returns a client connected to it.
func testClientServer(t *testing.T) *Conn {
	t.Helper()

	s := NewServer()
	s.EnforceLDAP = true
	s.SearchFunc("", searchSimple{})
	s.BindFunc("", bindAnonOK{})
	return dialTest(t, testServer(t, s))
}

func TestConnect(t *testing.T) {
	s := NewServer()
	s.BindFunc("", bindAnonOK{})
	addr := testServer(t, s)

	l, err := Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial(%s): %s", addr, err)
	}
	l.Close()
}

func TestSearch(t *testing.T) {
	l := testClientServer(t)

	searchRequest := NewSearchRequest(
		serverBaseDN,
		ScopeWholeSubtree, NeverDerefAliases, 0, 0, false,
		clientTestFilters[0],
		clientTestAttributes,
		nil)

	sr, err := l.Search(searchRequest)
	if err != nil {
		t.Fatalf("search %q: %s", searchRequest.Filter, err)
	}
	if len(sr.Entries) != clientTestEntries[0] {
		t.Fatalf("%s returned %d entries, want %d", searchRequest.Filter, len(sr.Entries), clientTestEntries[0])
	}
	if got := sr.Entries[0].GetAttributeValue("description"); got != "ned via sa" {
		t.Errorf("description is %q, want %q", got, "ned via sa")
	}
	// The server was asked for cn and description only.
	if got := sr.Entries[0].GetAttributeValue("uidNumber"); got != "" {
		t.Errorf("uidNumber came back as %q although it was not requested", got)
	}
}

func TestSearchWithPaging(t *testing.T) {
	l := testClientServer(t)

	if err := l.Bind("", ""); err != nil {
		t.Fatalf("bind failed: %s", err)
	}

	searchRequest := NewSearchRequest(
		serverBaseDN,
		ScopeWholeSubtree, NeverDerefAliases, 0, 0, false,
		clientTestFilters[1],
		clientTestAttributes,
		nil)
	sr, err := l.SearchWithPaging(searchRequest, 5)
	if err != nil {
		t.Fatalf("paged search %q: %s", searchRequest.Filter, err)
	}

	// The server does not implement the paging control, so it answers with
	// the whole result set and no cookie, and the client stops after one
	// round. Dropping entries here would mean the paging loop mishandled a
	// server that ignores the control.
	if len(sr.Entries) != clientTestEntries[1] {
		t.Errorf("%s returned %d entries, want %d", searchRequest.Filter, len(sr.Entries), clientTestEntries[1])
	}
}

func TestMultiGoroutineSearch(t *testing.T) {
	l := testClientServer(t)

	// Each goroutine reports over its own channel rather than calling
	// t.Error itself: an assertion from a goroutine that outlived the test
	// panics the whole test binary.
	type searchOutcome struct {
		result *SearchResult
		err    error
	}
	results := make([]chan searchOutcome, len(clientTestFilters))
	for i := range clientTestFilters {
		results[i] = make(chan searchOutcome, 1)
		go func(i int) {
			sr, err := l.Search(NewSearchRequest(
				serverBaseDN,
				ScopeWholeSubtree, NeverDerefAliases, 0, 0, false,
				clientTestFilters[i],
				clientTestAttributes,
				nil))
			results[i] <- searchOutcome{result: sr, err: err}
		}(i)
	}

	for i := range clientTestFilters {
		outcome := <-results[i]
		if outcome.err != nil {
			t.Errorf("search %q: %s", clientTestFilters[i], outcome.err)
			continue
		}
		if len(outcome.result.Entries) != clientTestEntries[i] {
			t.Errorf("%s returned %d entries, want %d",
				clientTestFilters[i], len(outcome.result.Entries), clientTestEntries[i])
		}
	}
}
