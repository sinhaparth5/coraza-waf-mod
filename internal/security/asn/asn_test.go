package asn

import "testing"

func newTestLookup(t *testing.T) *Lookup {
	t.Helper()
	l, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func TestLookupForConnReusesConnCache(t *testing.T) {
	l := newTestLookup(t)
	const remoteAddr = "203.0.113.1:12345"
	const ip = "8.8.8.8"

	wantASN, wantOrg := l.Lookup(ip)
	if wantASN == 0 {
		t.Fatal("expected a non-zero ASN for 8.8.8.8 from the bundled DB-IP Lite DB")
	}

	gotASN, gotOrg := l.LookupForConn(remoteAddr, ip)
	if gotASN != wantASN || gotOrg != wantOrg {
		t.Fatalf("first cached lookup = (%d, %q), want (%d, %q)", gotASN, gotOrg, wantASN, wantOrg)
	}

	// Break the underlying reader so a real (uncached) lookup would return
	// (0, ""). A second call still returning the same value proves the
	// cache was used instead of falling through to the broken reader.
	l.reader = nil
	gotASN, gotOrg = l.LookupForConn(remoteAddr, ip)
	if gotASN != wantASN || gotOrg != wantOrg {
		t.Fatalf("cached lookup after reader broke = (%d, %q), want (%d, %q) (cache was not reused)", gotASN, gotOrg, wantASN, wantOrg)
	}
}

func TestLookupForConnInvalidatesOnIPChange(t *testing.T) {
	l := newTestLookup(t)
	const remoteAddr = "203.0.113.2:12345"

	if asnNum, _ := l.LookupForConn(remoteAddr, "8.8.8.8"); asnNum == 0 {
		t.Fatal("expected a non-zero ASN for 8.8.8.8")
	}

	// Same remoteAddr (simulating a proxy connection reused for a different
	// real client), different IP: must not return 8.8.8.8's cached ASN.
	l.reader = nil
	if asnNum, org := l.LookupForConn(remoteAddr, "1.1.1.1"); asnNum != 0 || org != "" {
		t.Fatalf("lookup for a different IP on the same remoteAddr returned (%d, %q), want (0, \"\") (stale cache entry leaked across clients)", asnNum, org)
	}
}

func TestASNDeleteConnClearsCache(t *testing.T) {
	l := newTestLookup(t)
	const remoteAddr = "203.0.113.3:12345"
	const ip = "8.8.8.8"

	if asnNum, _ := l.LookupForConn(remoteAddr, ip); asnNum == 0 {
		t.Fatal("expected a non-zero ASN for 8.8.8.8")
	}

	DeleteConn(remoteAddr)
	l.reader = nil
	if asnNum, org := l.LookupForConn(remoteAddr, ip); asnNum != 0 || org != "" {
		t.Fatalf("lookup after DeleteConn = (%d, %q), want (0, \"\") (entry should have been evicted, forcing a fresh — and here broken — lookup)", asnNum, org)
	}
}

func TestLookupForConnNilLookup(t *testing.T) {
	var l *Lookup
	if asnNum, org := l.LookupForConn("203.0.113.4:12345", "8.8.8.8"); asnNum != 0 || org != "" {
		t.Fatalf("nil *Lookup.LookupForConn = (%d, %q), want (0, \"\")", asnNum, org)
	}
}
