package tests

import (
	"testing"

	"bareport/scanner"
)

// FuzzClassifyBanner fuzzes scanner.ClassifyBanner — the parser that
// turns whatever bytes a scanned service sends back first into a
// protocol guess (ssh/http/ftp/smtp/unknown-text/raw). This is
// genuinely untrusted input: the string being parsed is whatever a
// remote (possibly hostile) service chose to send, so a parser bug
// here is a real, if low-severity, attack surface — bareport
// shouldn't be able to be made to panic just by scanning a service
// that sends back a deliberately weird banner.
//
// Uses Go's native fuzzing engine (`testing.F`, stdlib since Go
// 1.18) — no third-party fuzzing library. That's worth calling out
// explicitly: most languages need an external fuzzing framework
// (AFL, libFuzzer bindings, a dedicated package) to get this kind of
// coverage-guided input generation at all; Go ships it in `go test`
// itself.
func FuzzClassifyBanner(f *testing.F) {
	// Seed corpus: valid examples of every branch, plus edge cases
	// already known to matter (empty string, non-UTF8 bytes, a "220"
	// prefix that's neither SMTP nor FTP, a string that's exactly at
	// the looksLikeSMTPOrFTP length boundary).
	seeds := []string{
		"SSH-2.0-OpenSSH_9.3",
		"HTTP/1.1 200 OK",
		"220 mail.example.com ESMTP Postfix",
		"220 FTP server ready",
		"",
		"220",                  // exactly the SMTP/FTP prefix, nothing after it
		"2201",                 // "220" prefix but len()==4, boundary of looksLikeSMTPOrFTP
		"SSH-",                 // prefix only, no version string after it
		"HTTP/",                // prefix only
		"\x00\x01\x02\xff\xfe", // raw non-printable bytes
		"\xc3\x28",             // invalid UTF-8 sequence
		"plain unrecognized text",
		"SSH-2.0-" + string(make([]byte, 500)), // long input
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, line string) {
		// The only real invariant: ClassifyBanner must never panic on
		// any input, and must always return a non-nil *Banner with a
		// non-empty Protocol field — every branch in classifyBanner
		// sets Protocol, so an empty one would indicate a code path
		// this test didn't anticipate.
		b := scanner.ClassifyBanner(line)
		if b == nil {
			t.Fatalf("ClassifyBanner(%q) returned nil", line)
		}
		if b.Protocol == "" {
			t.Fatalf("ClassifyBanner(%q) returned a Banner with empty Protocol: %+v", line, b)
		}
		// Exactly one of Raw/HexDump should carry the content —
		// never both, since the raw/hex-dump fallback path is
		// mutually exclusive with every text-classified path.
		if b.Raw != "" && b.HexDump != "" {
			t.Fatalf("ClassifyBanner(%q) set both Raw and HexDump: %+v", line, b)
		}
	})
}
