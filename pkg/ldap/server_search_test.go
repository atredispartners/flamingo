package ldap

import (
	"testing"
)

// testSearchClient starts a server with the given search handler and returns a
// client already bound as the user bindSimple{} accepts.
func testSearchClient(t *testing.T, enforceLDAP bool, searcher Searcher) *Conn {
	t.Helper()

	s := NewServer()
	s.EnforceLDAP = enforceLDAP
	s.SearchFunc("", searcher)
	s.BindFunc("", bindSimple{})

	l := dialTest(t, testServer(t, s))
	if err := l.Bind("cn=testy,"+serverBaseDN, "iLike2test"); err != nil {
		t.Fatalf("bind failed: %s", err)
	}
	return l
}

// search runs one search and fails the test if the server refuses it.
func search(t *testing.T, l *Conn, baseDN string, scope, sizeLimit int, filter string, attributes []string, controls []Control) *SearchResult {
	t.Helper()

	res, err := l.Search(NewSearchRequest(baseDN, scope, NeverDerefAliases, sizeLimit, 0, false, filter, attributes, controls))
	if err != nil {
		t.Fatalf("search %q under %q: %s", filter, baseDN, err)
	}
	return res
}

// hasDN reports whether a search result contains the given DN.
func hasDN(res *SearchResult, dn string) bool {
	for _, e := range res.Entries {
		if e.DN == dn {
			return true
		}
	}
	return false
}

func TestSearchSimpleOK(t *testing.T) {
	l := testSearchClient(t, false, searchSimple{})

	res := searchAll(t, l, serverBaseDN)
	if len(res.Entries) != 3 {
		t.Fatalf("expected 3 entries, got %d: %v", len(res.Entries), entryDNs(res))
	}
	if !hasDN(res, "cn=ned,o=testers,c=test") {
		t.Errorf("missing cn=ned: %v", entryDNs(res))
	}
	if got := res.Entries[0].GetAttributeValue("uidNumber"); got != "5000" {
		t.Errorf("uidNumber of the first entry is %q, want 5000", got)
	}
}

func TestSearchSizelimit(t *testing.T) {
	l := testSearchClient(t, true, searchSimple{})

	// A size limit of 0 means unlimited, matching ldapsearch -z 0.
	for _, tc := range []struct {
		name        string
		sizeLimit   int
		filter      string
		wantEntries int
	}{
		{name: "unlimited", sizeLimit: 0, filter: "(objectclass=*)", wantEntries: 3},
		{name: "above the result count", sizeLimit: 9, filter: "(objectclass=*)", wantEntries: 3},
		{name: "two", sizeLimit: 2, filter: "(objectclass=*)", wantEntries: 2},
		{name: "one", sizeLimit: 1, filter: "(objectclass=*)", wantEntries: 1},
		{name: "one with filter", sizeLimit: 1, filter: "(uid=trent)", wantEntries: 1},
		{name: "unlimited with filter", sizeLimit: 0, filter: "(uid=trent)", wantEntries: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := search(t, l, serverBaseDN, ScopeWholeSubtree, tc.sizeLimit, tc.filter, nil, nil)
			if len(res.Entries) != tc.wantEntries {
				t.Errorf("size limit %d with filter %q returned %d entries, want %d: %v",
					tc.sizeLimit, tc.filter, len(res.Entries), tc.wantEntries, entryDNs(res))
			}
		})
	}
}

// ///////////////////////
func TestBindSearchMulti(t *testing.T) {
	s := NewServer()
	s.BindFunc("", bindSimple{})
	s.BindFunc("c=testz", bindSimple2{})
	s.SearchFunc("", searchSimple{})
	s.SearchFunc("c=testz", searchSimple2{})
	addr := testServer(t, s)

	// A bind is routed on the bind DN and a search on its base DN, so each
	// half of the routing is exercised on its own connection.
	def := dialTest(t, addr)
	if err := def.Bind("cn=testy,o=testers,c=test", "iLike2test"); err != nil {
		t.Fatalf("default bind routing failed: %s", err)
	}
	res := search(t, def, "o=testers,c=test", ScopeWholeSubtree, 0, "(cn=ned)", nil, nil)
	if !hasDN(res, "cn=ned,o=testers,c=test") {
		t.Errorf("default search routing failed: %v", entryDNs(res))
	}

	custom := dialTest(t, addr)
	if err := custom.Bind("cn=testy,o=testers,c=testz", "ZLike2test"); err != nil {
		t.Fatalf("custom bind routing failed: %s", err)
	}
	res = search(t, custom, "o=testers,c=testz", ScopeWholeSubtree, 0, "(cn=hamburger)", nil, nil)
	if !hasDN(res, "cn=hamburger,o=testers,c=testz") {
		t.Errorf("custom search routing failed: %v", entryDNs(res))
	}

	// The handler registered under c=testz must not answer for the default
	// base DN, nor the other way round.
	if res = search(t, def, "o=testers,c=test", ScopeWholeSubtree, 0, "(cn=hamburger)", nil, nil); hasDN(res, "cn=hamburger,o=testers,c=testz") {
		t.Errorf("default search returned an entry from the c=testz handler: %v", entryDNs(res))
	}
}

// ///////////////////////
func TestSearchPanic(t *testing.T) {
	s := NewServer()
	s.SearchFunc("", searchPanic{})
	s.BindFunc("", bindAnonOK{})

	l := dialTest(t, testServer(t, s))
	if err := l.Bind("", ""); err != nil {
		t.Fatalf("bind failed: %s", err)
	}

	_, err := l.Search(NewSearchRequest(serverBaseDN, ScopeWholeSubtree, NeverDerefAliases, 0, 0, false, "(objectclass=*)", nil, nil))
	if err == nil {
		t.Fatal("search succeeded although the handler panicked")
	}
	if code := resultCode(t, err); code != LDAPResultOperationsError {
		t.Errorf("expected operations error after handler panic, got %d", code)
	}
}

// ///////////////////////
type compileSearchFilterTest struct {
	name       string
	filterStr  string
	numEntries int
}

// The entry counts here are one less than the numResponses the ldapsearch
// version of this test asserted on, since that count included the search-done
// message.
var searchFilterTestFilters = []compileSearchFilterTest{
	{name: "equalityOk", filterStr: "(uid=ned)", numEntries: 1},
	{name: "equalityNo", filterStr: "(uid=foo)", numEntries: 0},
	{name: "equalityObjectclassOk", filterStr: "(objectclass=posixaccount)", numEntries: 3},
	// ldapsearch defaults to this filter when given an empty one, which is
	// the case the "presentEmptyOk" row used to cover; the client here has
	// no such default and rejects an empty filter.
	{name: "presentDefaultOk", filterStr: "(objectclass=*)", numEntries: 3},
	{name: "presentDescriptionOk", filterStr: "(description=*)", numEntries: 2},
	{name: "presentNo", filterStr: "(foo=*)", numEntries: 0},
	{name: "andOk", filterStr: "(&(uid=ned)(objectclass=posixaccount))", numEntries: 1},
	{name: "andNoObjectclass", filterStr: "(&(uid=ned)(objectclass=posixgroup))", numEntries: 0},
	{name: "andNoBothUids", filterStr: "(&(uid=ned)(uid=trent))", numEntries: 0},
	{name: "orOk", filterStr: "(|(uid=ned)(uid=trent))", numEntries: 2},
	{name: "orObjectclassOk", filterStr: "(|(uid=ned)(objectclass=posixaccount))", numEntries: 3},
	{name: "orNo", filterStr: "(|(uid=foo)(objectclass=foo))", numEntries: 0},
	{name: "andOrOk", filterStr: "(&(|(uid=ned)(uid=trent))(objectclass=posixaccount))", numEntries: 2},
	{name: "notOk", filterStr: "(!(uid=ned))", numEntries: 2},
	{name: "notNoMatch", filterStr: "(!(uid=foo))", numEntries: 3},
	{name: "notAndOrOk", filterStr: "(&(|(uid=ned)(uid=trent))(!(objectclass=posixgroup)))", numEntries: 2},
	{name: "substringInitialOk", filterStr: "(uid=ne*)", numEntries: 1},
	{name: "substringFinalOk", filterStr: "(uid=*ent)", numEntries: 1},
	{name: "substringAnyOk", filterStr: "(description=*via*)", numEntries: 2},
	{name: "substringNo", filterStr: "(uid=zz*)", numEntries: 0},
	/*
		compileSearchFilterTest{filterStr: "(sn>=Miller)", filterType: FilterGreaterOrEqual},
		compileSearchFilterTest{filterStr: "(sn<=Miller)", filterType: FilterLessOrEqual},
		compileSearchFilterTest{filterStr: "(sn~=Miller)", filterType: FilterApproxMatch},
	*/
}

// ///////////////////////
func TestSearchFiltering(t *testing.T) {
	l := testSearchClient(t, true, searchSimple{})

	for _, tc := range searchFilterTestFilters {
		t.Run(tc.name, func(t *testing.T) {
			res := search(t, l, serverBaseDN, ScopeWholeSubtree, 0, tc.filterStr, nil, nil)
			if len(res.Entries) != tc.numEntries {
				t.Errorf("filter %q returned %d entries, want %d: %v",
					tc.filterStr, len(res.Entries), tc.numEntries, entryDNs(res))
			}
		})
	}
}

// ///////////////////////
func TestSearchAttributes(t *testing.T) {
	l := testSearchClient(t, true, searchSimple{})

	res := search(t, l, serverBaseDN, ScopeWholeSubtree, 0, "(objectclass=*)", []string{"cn"}, nil)
	if !hasDN(res, "cn=ned,o=testers,c=test") {
		t.Fatalf("missing cn=ned: %v", entryDNs(res))
	}
	for _, e := range res.Entries {
		names := []string{}
		for _, a := range e.Attributes {
			names = append(names, a.Name)
		}
		if len(names) != 1 || names[0] != "cn" {
			t.Errorf("%s returned attributes %v, want cn only", e.DN, names)
		}
	}
	if got := res.Entries[0].GetAttributeValue("cn"); got != "ned" {
		t.Errorf("cn of the first entry is %q, want ned", got)
	}
}

func TestSearchAllUserAttributes(t *testing.T) {
	l := testSearchClient(t, true, searchSimple{})

	res := search(t, l, serverBaseDN, ScopeWholeSubtree, 0, "(objectclass=*)", []string{"*"}, nil)
	if !hasDN(res, "cn=ned,o=testers,c=test") {
		t.Fatalf("missing cn=ned: %v", entryDNs(res))
	}
	ned := res.Entries[0]
	for _, want := range []struct{ attr, value string }{
		{"cn", "ned"},
		{"o", "ate"},
		{"uidNumber", "5000"},
		{"accountstatus", "active"},
		{"description", "ned via sa"},
		{"objectclass", "posixaccount"},
	} {
		if got := ned.GetAttributeValue(want.attr); got != want.value {
			t.Errorf("%s is %q, want %q", want.attr, got, want.value)
		}
	}
}

// ///////////////////////
func TestSearchScope(t *testing.T) {
	l := testSearchClient(t, true, searchSimple{})

	const trent = "cn=trent,o=testers,c=test"
	for _, tc := range []struct {
		name   string
		baseDN string
		scope  int
		wantDN bool
	}{
		{name: "subFromRoot", baseDN: "c=test", scope: ScopeWholeSubtree, wantDN: true},
		{name: "oneFromParent", baseDN: "o=testers,c=test", scope: ScopeSingleLevel, wantDN: true},
		{name: "oneFromGrandparent", baseDN: "c=test", scope: ScopeSingleLevel, wantDN: false},
		{name: "baseOnEntry", baseDN: trent, scope: ScopeBaseObject, wantDN: true},
		{name: "baseOnParent", baseDN: "o=testers,c=test", scope: ScopeBaseObject, wantDN: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := search(t, l, tc.baseDN, tc.scope, 0, "(cn=trent)", nil, nil)
			if got := hasDN(res, trent); got != tc.wantDN {
				t.Errorf("scope %d under %q: found %s = %t, want %t", tc.scope, tc.baseDN, trent, got, tc.wantDN)
			}
		})
	}
}

func TestSearchControls(t *testing.T) {
	l := testSearchClient(t, false, searchControls{})

	controls := []Control{NewControlString("1.2.3.4.5", false, "")}
	res := search(t, l, serverBaseDN, ScopeWholeSubtree, 0, "(objectclass=*)", nil, controls)
	if len(res.Entries) != 1 || !hasDN(res, "cn=hamburger,o=testers,c=testz") {
		t.Errorf("search with control returned %v, want cn=hamburger only", entryDNs(res))
	}

	res = search(t, l, serverBaseDN, ScopeWholeSubtree, 0, "(objectclass=*)", nil, nil)
	if len(res.Entries) != 0 {
		t.Errorf("search without control returned %v, want no entries", entryDNs(res))
	}
}
