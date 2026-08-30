package tests

import (
	"strings"
	"testing"

	"bareport/selfaudit"
)

// TestSelfAudit_Verify_CurrentBuildIsZeroDep runs the real check
// against the real generated manifest committed alongside this test —
// this is the same code path `bareport --verify-zero-dep` runs, so a
// stray `require` line or a genuinely non-stdlib import anywhere in
// bareport's own dependency graph fails this test, not just a manual
// `--verify-zero-dep` run someone might forget to do before merging.
func TestSelfAudit_Verify_CurrentBuildIsZeroDep(t *testing.T) {
	r := selfaudit.Verify()

	if r.ModulePath != "bareport" {
		t.Errorf("expected ModulePath %q, got %q", "bareport", r.ModulePath)
	}
	if r.RequireLineCount != 0 {
		t.Errorf("expected 0 require lines in go.mod, got %d", r.RequireLineCount)
	}
	if r.ImportsWalked == 0 {
		t.Fatal("expected a non-zero import graph — manifest_generated.go may be empty or stale; run `go run tools/gen_selfaudit.go`")
	}
	if !r.Verified() {
		t.Errorf("expected the current build to verify clean, found imports outside stdlib: %v", r.OutsideStdlib)
	}
}

// TestSelfAudit_Verify_TreatsOwnPackagesAsFine confirms bareport's own
// packages (module path itself, and anything under it) never count as
// a violation — the whole point of the check is finding *third-party*
// imports, not flagging bareport's own multi-package structure.
func TestSelfAudit_Verify_TreatsOwnPackagesAsFine(t *testing.T) {
	r := selfaudit.Verify()
	for _, v := range r.OutsideStdlib {
		if v == "bareport" || strings.HasPrefix(v, "bareport/") {
			t.Errorf("bareport's own package %q should never be reported as outside stdlib", v)
		}
	}
}

// TestSelfAudit_Result_Verified_MatchesOutsideStdlibLength is a direct
// check on the Verified() helper's contract: true if and only if
// OutsideStdlib is empty.
func TestSelfAudit_Result_Verified_MatchesOutsideStdlibLength(t *testing.T) {
	clean := selfaudit.Result{}
	if !clean.Verified() {
		t.Error("expected Result{} (no violations) to report Verified() == true")
	}
	dirty := selfaudit.Result{OutsideStdlib: []string{"github.com/example/pkg"}}
	if dirty.Verified() {
		t.Error("expected a Result with a non-empty OutsideStdlib to report Verified() == false")
	}
}
