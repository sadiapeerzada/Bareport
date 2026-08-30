package selfaudit

// Verify()'s FAILED branch (something outside stdlib actually found)
// can't be exercised through the real, generated ownImports table —
// by construction, on a genuinely zero-dependency build that table
// never contains a violation, and it shouldn't: faking a real
// violation into the generated manifest file would defeat the whole
// point of --verify-zero-dep. Since ownImports is an ordinary
// package-level var (not a const), an in-package test can temporarily
// substitute it with a synthetic entry, call the real Verify() logic
// against that substitute, and restore the original afterward — this
// tests Verify()'s actual branching logic directly without touching
// (or permanently faking) the generated data file itself.

import "testing"

func TestVerify_FlagsAGenuineOutsideStdlibImport(t *testing.T) {
	original := ownImports
	defer func() { ownImports = original }()

	ownImports = []string{
		"bareport",
		"bareport/cli",
		"fmt",                                // real stdlib, should be treated as fine
		"github.com/some/thirdparty/package", // the injected violation
	}

	r := Verify()

	if r.Verified() {
		t.Fatal("expected Verify() to report NOT verified given a genuine outside-stdlib import")
	}
	if len(r.OutsideStdlib) != 1 || r.OutsideStdlib[0] != "github.com/some/thirdparty/package" {
		t.Errorf("expected OutsideStdlib to contain exactly the injected violation, got %v", r.OutsideStdlib)
	}
	if r.ImportsWalked != len(ownImports) {
		t.Errorf("expected ImportsWalked to equal len(ownImports) (%d), got %d", len(ownImports), r.ImportsWalked)
	}
}

func TestVerify_TreatsVendorPrefixedImportsAsFine(t *testing.T) {
	original := ownImports
	defer func() { ownImports = original }()

	ownImports = []string{
		"vendor/golang.org/x/net/http2/hpack", // stdlib's own internal vendoring
	}

	r := Verify()
	if !r.Verified() {
		t.Errorf("expected a vendor/-prefixed import to be treated as fine, got OutsideStdlib=%v", r.OutsideStdlib)
	}
}
