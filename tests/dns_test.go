package tests

import (
	"context"
	"testing"
	"time"

	"bareport/scanner"
)

// These tests exercise scanner.HasSPFRecord/HasDMARCRecord — the pure
// parsing logic split out of scanner.InspectDNS specifically for
// network-independent testability (see scanner/dns.go's doc comment on
// those two functions for why). No network call happens in any test
// in this file.

func TestDNS_HasSPFRecord(t *testing.T) {
	cases := []struct {
		name    string
		records []string
		want    bool
	}{
		{"present, lowercase", []string{"v=spf1 include:_spf.example.com ~all"}, true},
		{"present, mixed case", []string{"V=SPF1 include:_spf.example.com ~all"}, true},
		{"present among other TXT records", []string{"some-other-txt-record", "v=spf1 -all"}, true},
		{"absent", []string{"some-other-txt-record"}, false},
		{"empty", nil, false},
		{"similar but not SPF", []string{"v=spf2 include:_spf.example.com ~all"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := scanner.HasSPFRecord(c.records); got != c.want {
				t.Errorf("HasSPFRecord(%v) = %v, want %v", c.records, got, c.want)
			}
		})
	}
}

func TestDNS_HasDMARCRecord(t *testing.T) {
	cases := []struct {
		name    string
		records []string
		want    bool
	}{
		{"present, lowercase", []string{"v=dmarc1; p=reject;"}, true},
		{"present, mixed case", []string{"V=DMARC1; p=none;"}, true},
		{"present among other TXT records", []string{"unrelated", "v=dmarc1; p=quarantine;"}, true},
		{"absent", []string{"unrelated"}, false},
		{"empty", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := scanner.HasDMARCRecord(c.records); got != c.want {
				t.Errorf("HasDMARCRecord(%v) = %v, want %v", c.records, got, c.want)
			}
		})
	}
}

// TestDNS_InspectDNS_NetworkDependent_NoteAndSmokeCheck documents, in
// code (not just a comment), why InspectDNS's live-lookup path is
// integration-tested rather than unit-tested: net.Resolver has no
// dependency-injectable transport in the standard library, so testing
// it "for real" means either a genuine network DNS query (non-
// deterministic in a sandboxed/offline CI environment — it may have no
// route to a real resolver at all) or a hand-rolled fake resolver
// (which tests the fake, not this code). This test is intentionally a
// smoke check only: it asserts InspectDNS doesn't panic or hang past a
// bounded timeout and always returns a non-nil *DNSInfo even when
// every lookup fails outright (e.g. no network / no resolver
// reachable) — the one behavior that IS meaningfully testable without
// a real, reachable DNS infrastructure. The actual "did we correctly
// detect SPF/DMARC" behavior is covered by the two tests above
// (pure logic) plus `make integration-test`'s --dns-driven checks
// against reachable infrastructure.
//
// The outer context here is deliberately given far MORE headroom than
// the timeout passed to InspectDNS itself (5s vs. 1s), so this test
// actually exercises InspectDNS's own internal bound rather than
// riding on a caller-supplied deadline — see InspectDNS's doc comment
// for why it now takes a timeout parameter instead of trusting ctx to
// already carry one.
func TestDNS_InspectDNS_NetworkDependent_NoteAndSmokeCheck(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// A hostname guaranteed not to resolve (reserved by RFC 2606 for
	// documentation/testing, never delegated) — this exercises the
	// "every lookup fails" path deterministically, without depending
	// on any specific real domain's DNS records staying stable.
	info, err := scanner.InspectDNS(ctx, "this-host-does-not-exist.invalid", 1*time.Second)
	if err != nil {
		t.Fatalf("InspectDNS should not return an error even when nothing resolves, got: %v", err)
	}
	if info == nil {
		t.Fatal("InspectDNS should always return a non-nil *DNSInfo, even on total lookup failure")
	}
	if len(info.Addresses) != 0 {
		t.Errorf("expected no addresses for a .invalid hostname, got %v", info.Addresses)
	}
}

// TestDNS_InspectDNS_BoundsItselfWithoutCallerDeadline is the
// regression test for the actual bug: it passes a ctx with NO
// deadline of its own (context.Background(), same as
// orchestrate.go's ctx before this fix — only ever cancelled by
// Ctrl+C/SIGTERM, never by a timeout) and asserts InspectDNS still
// returns within its own short timeout instead of hanging until the
// test binary is killed. Before the fix, this exact call shape would
// block indefinitely against an unresponsive resolver.
func TestDNS_InspectDNS_BoundsItselfWithoutCallerDeadline(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = scanner.InspectDNS(context.Background(), "this-host-does-not-exist.invalid", 500*time.Millisecond)
	}()

	select {
	case <-done:
		// returned on its own — correct.
	case <-time.After(5 * time.Second):
		t.Fatal("InspectDNS did not return within a bounded time given a caller context with no deadline of its own")
	}
}
