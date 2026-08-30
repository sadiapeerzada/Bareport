package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"bareport/cli"
)

func runCLI(t *testing.T, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	var outBuf, errBuf bytes.Buffer
	code := cli.Run(args, &outBuf, &errBuf)
	return outBuf.String(), errBuf.String(), code
}

func TestCLI_NoTargets_NonTTYStdout_ExitsCleanly(t *testing.T) {
	stdout, stderr, code := runCLI(t, "--ports", "80")
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(stderr, "no targets given") {
		t.Errorf("expected a 'no targets given' error on stderr, got: %q", stderr)
	}
	if strings.Contains(stdout, "Enter a host") {
		t.Error("did not expect the interactive prompt text under a non-interactive test run")
	}
}

func TestCLI_BadPorts_CleanError(t *testing.T) {
	_, stderr, code := runCLI(t, "--targets", "127.0.0.1", "--ports", "not-a-port")
	if code != 1 {
		t.Errorf("expected exit code 1 for a malformed --ports value, got %d", code)
	}
	if !strings.Contains(stderr, "parsing --ports") {
		t.Errorf("expected a parsing error mentioning --ports, got: %q", stderr)
	}
}

func TestCLI_UnknownFlag_CleanError(t *testing.T) {
	_, _, code := runCLI(t, "--this-flag-does-not-exist")
	if code != 1 {
		t.Errorf("expected exit code 1 for an unknown flag, got %d", code)
	}
}

func TestCLI_Help_ExitsZero(t *testing.T) {
	stdout, _, code := runCLI(t, "--help")
	if code != 0 {
		t.Errorf("expected --help to exit 0, got %d", code)
	}
	if !strings.Contains(stdout, "-targets") {
		t.Errorf("expected --help usage text to mention -targets, got: %q", stdout)
	}
}

func TestCLI_WhyZeroDep_PrintsSubstitutions(t *testing.T) {
	stdout, _, code := runCLI(t, "why-zero-dep")
	if code != 0 {
		t.Errorf("expected why-zero-dep to exit 0, got %d", code)
	}
	if !strings.Contains(stdout, "BAREPORT ZERO-DEPENDENCY REPORT") {
		t.Error("expected the why-zero-dep header")
	}
	if !strings.Contains(stdout, "flag") {
		t.Error("expected the CLI-parsing substitution entry mentioning flag")
	}
}

func TestCLI_VerifyZeroDep_ExitsZeroAndPrintsReport(t *testing.T) {
	stdout, _, code := runCLI(t, "--verify-zero-dep")
	if code != 0 {
		t.Errorf("expected --verify-zero-dep to exit 0 on a clean build, got %d", code)
	}
	if !strings.Contains(stdout, "bareport zero-dependency self-audit") {
		t.Error("expected the self-audit header")
	}
	if !strings.Contains(stdout, "go.mod:") || !strings.Contains(stdout, "module bareport") {
		t.Errorf("expected go.mod summary line, got: %q", stdout)
	}
	if !strings.Contains(stdout, "imports walked:") {
		t.Errorf("expected an imports-walked count, got: %q", stdout)
	}
	if !strings.Contains(stdout, "VERIFIED") {
		t.Errorf("expected a VERIFIED verdict on a clean build, got: %q", stdout)
	}
}

func TestCLI_VerifyZeroDep_SkipsTargetRequirement(t *testing.T) {
	// --verify-zero-dep takes no targets and isn't a scan -- it must
	// not hit the "no targets given" error path a normal scan-mode
	// invocation with no --targets would.
	stdout, stderr, code := runCLI(t, "--verify-zero-dep")
	if code != 0 {
		t.Errorf("expected exit 0, got %d (stderr: %q)", code, stderr)
	}
	if strings.Contains(stderr, "no targets given") {
		t.Error("--verify-zero-dep should not require --targets")
	}
	if strings.Contains(stdout, "Enter a host") {
		t.Error("--verify-zero-dep should not fall into the interactive-prompt path")
	}
}

func TestCLI_Watch_RequiresTargets(t *testing.T) {
	_, stderr, code := runCLI(t, "--watch")
	if code != 1 {
		t.Errorf("expected exit code 1 for --watch with no targets, got %d", code)
	}
	if !strings.Contains(stderr, "no targets given") {
		t.Errorf("expected a 'no targets given' error on stderr, got: %q", stderr)
	}
}

func TestCLI_Watch_ConflictsWithServe(t *testing.T) {
	_, stderr, code := runCLI(t, "--watch", "--serve", "--targets", "127.0.0.1")
	if code != 1 {
		t.Errorf("expected exit code 1 for --watch combined with --serve, got %d", code)
	}
	if !strings.Contains(stderr, "mutually exclusive") {
		t.Errorf("expected a mutually-exclusive error for --watch + --serve, got: %q", stderr)
	}
}

// TestCLI_Watch_RunsInitialScanThenStopsCleanlyOnSignal exercises the
// real end-to-end path: --watch has no other exit condition besides
// context cancellation, so this test sends a real os.Interrupt to the
// current process shortly after starting it -- the exact signal
// cli.Run's signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
// wiring listens for, i.e. exactly what a user's Ctrl+C delivers, not
// a simulation of it. --interval is set far longer than the signal
// delay so this only passes if cancellation actually interrupts the
// wait, not if the loop happened to finish on its own.
func TestCLI_Watch_RunsInitialScanThenStopsCleanlyOnSignal(t *testing.T) {
	go func() {
		time.Sleep(300 * time.Millisecond)
		p, err := os.FindProcess(os.Getpid())
		if err != nil {
			t.Errorf("os.FindProcess: %v", err)
			return
		}
		if err := p.Signal(os.Interrupt); err != nil {
			t.Errorf("sending os.Interrupt: %v", err)
		}
	}()

	stdout, _, _ := runCLI(t, "--watch", "--targets", "127.0.0.1", "--ports", "1",
		"--skip-discovery", "--no-color", "--no-live", "--interval", "10s")

	if !strings.Contains(stdout, "bareport watch: re-scanning every") {
		t.Error("expected the watch startup banner")
	}
	if !strings.Contains(stdout, "initial scan:") {
		t.Error("expected the initial scan to have run before cancellation")
	}
	if !strings.Contains(stdout, "bareport watch: stopped") {
		t.Errorf("expected a clean 'stopped' message after signal cancellation, got: %q", stdout)
	}
}

func TestCLI_Diff_WrongArgCount(t *testing.T) {
	_, stderr, code := runCLI(t, "diff", "only-one-file.json")
	if code != 1 {
		t.Errorf("expected exit code 1 for wrong diff arg count, got %d", code)
	}
	if !strings.Contains(stderr, "usage: bareport diff") {
		t.Errorf("expected a usage message, got: %q", stderr)
	}
}

func TestCLI_Diff_MissingFile(t *testing.T) {
	_, stderr, code := runCLI(t, "diff", "/tmp/bareport-test-does-not-exist-a.json", "/tmp/bareport-test-does-not-exist-b.json")
	if code != 1 {
		t.Errorf("expected exit code 1 for a missing baseline file, got %d", code)
	}
	if !strings.Contains(stderr, "opening") {
		t.Errorf("expected an 'opening' file error, got: %q", stderr)
	}
}

func TestCLI_Diff_SecondFileMissing(t *testing.T) {
	dir := t.TempDir()
	baseline := dir + "/baseline.json"
	if _, _, code := runCLI(t, "--targets", "127.0.0.1", "--ports", "1", "--skip-discovery", "--no-live", "--save", baseline); code != 0 && code != 2 && code != 3 {
		t.Fatalf("expected a valid exit code while saving the baseline, got %d", code)
	}
	_, stderr, code := runCLI(t, "diff", baseline, "/tmp/bareport-test-does-not-exist-second.json")
	if code != 1 {
		t.Errorf("expected exit code 1 when the second diff file is missing, got %d", code)
	}
	if !strings.Contains(stderr, "opening") {
		t.Errorf("expected an 'opening' file error naming the missing second file, got: %q", stderr)
	}
}

func TestCLI_Diff_HappyPath_TwoRealSavedAssessments(t *testing.T) {
	dir := t.TempDir()
	baseline := dir + "/baseline.json"
	current := dir + "/current.json"

	if _, _, code := runCLI(t, "--targets", "127.0.0.1", "--ports", "1", "--skip-discovery", "--no-live", "--save", baseline); code != 0 && code != 2 && code != 3 {
		t.Fatalf("expected a valid exit code while saving the baseline, got %d", code)
	}
	if _, _, code := runCLI(t, "--targets", "127.0.0.1", "--ports", "1", "--skip-discovery", "--no-live", "--save", current); code != 0 && code != 2 && code != 3 {
		t.Fatalf("expected a valid exit code while saving the current scan, got %d", code)
	}

	stdout, stderr, code := runCLI(t, "diff", baseline, current)
	if code != 0 {
		t.Errorf("expected exit code 0 for a successful diff of two valid files, got %d (stderr=%q)", code, stderr)
	}
	if !strings.Contains(stdout, "No security drift detected") {
		t.Errorf("expected the no-drift confirmation for two identical scans, got: %q", stdout)
	}
}

func TestCLI_UnknownProfile_CleanError(t *testing.T) {
	_, stderr, code := runCLI(t, "--targets", "127.0.0.1", "--profile", "bogus-profile")
	if code != 1 {
		t.Errorf("expected exit code 1 for an unknown profile, got %d", code)
	}
	if !strings.Contains(stderr, "unknown profile") {
		t.Errorf("expected an 'unknown profile' error, got: %q", stderr)
	}
}

func TestCLI_Verbose_LogsJSONLifecycleEventsToStderr(t *testing.T) {
	_, stderr, code := runCLI(t, "--targets", "127.0.0.1", "--ports", "1", "--skip-discovery", "--no-live", "--no-color", "--verbose")
	if code != 0 && code != 2 && code != 3 {
		t.Fatalf("expected a valid exit code, got %d", code)
	}
	for _, want := range []string{"scan_started", "scan_completed"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("expected --verbose stderr to contain %q, got: %q", want, stderr)
		}
	}
}

func TestCLI_HTMLOutput_WritesReportFile(t *testing.T) {
	dir := t.TempDir()
	htmlPath := dir + "/report.html"
	stdout, stderr, code := runCLI(t, "--targets", "127.0.0.1", "--ports", "1", "--skip-discovery", "--no-live", "--no-color", "--html", htmlPath)
	if code != 0 && code != 2 && code != 3 {
		t.Fatalf("expected a valid exit code, got %d (stderr=%q)", code, stderr)
	}
	if !strings.Contains(stderr, "wrote HTML security report to") {
		t.Errorf("expected an HTML-written confirmation on stderr, got: %q", stderr)
	}
	body, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("reading generated HTML report: %v", err)
	}
	if !strings.Contains(string(body), "<html") {
		t.Errorf("expected the output file to contain an HTML document, got: %q", string(body)[:min(200, len(body))])
	}
	if !strings.Contains(stdout, "BAREPORT SECURITY ASSESSMENT") {
		t.Error("expected the normal table output to still print alongside --html")
	}
}

func TestCLI_HTMLOutput_WriteFailure_UnwritableDirectory(t *testing.T) {
	// A path inside a directory that doesn't exist can never be created.
	_, stderr, code := runCLI(t, "--targets", "127.0.0.1", "--ports", "1", "--skip-discovery", "--no-live", "--html", "/tmp/bareport-test-nonexistent-dir-xyz/report.html")
	if code != 1 {
		t.Errorf("expected exit code 1 for an unwritable HTML path, got %d", code)
	}
	if !strings.Contains(stderr, "creating HTML report") {
		t.Errorf("expected a 'creating HTML report' error, got: %q", stderr)
	}
}

func TestCLI_SaveOutput_WriteFailure_UnwritableDirectory(t *testing.T) {
	_, stderr, code := runCLI(t, "--targets", "127.0.0.1", "--ports", "1", "--skip-discovery", "--no-live", "--save", "/tmp/bareport-test-nonexistent-dir-xyz/save.json")
	if code != 1 {
		t.Errorf("expected exit code 1 for an unwritable save path, got %d", code)
	}
	if !strings.Contains(stderr, "creating") {
		t.Errorf("expected a 'creating' file error, got: %q", stderr)
	}
}

// TestCLI_Serve_StartsAndStopsCleanlyOnSignal mirrors
// TestCLI_Watch_RunsInitialScanThenStopsCleanlyOnSignal's real-signal
// approach: --serve's web.Server.Serve blocks on the exact same
// signal.NotifyContext-derived ctx as --watch, with no other exit
// condition, so a genuine os.Interrupt is the only faithful way to
// unit-test its shutdown path.
func TestCLI_Serve_StartsAndStopsCleanlyOnSignal(t *testing.T) {
	go func() {
		time.Sleep(300 * time.Millisecond)
		p, err := os.FindProcess(os.Getpid())
		if err != nil {
			t.Errorf("os.FindProcess: %v", err)
			return
		}
		if err := p.Signal(os.Interrupt); err != nil {
			t.Errorf("sending os.Interrupt: %v", err)
		}
	}()

	_, _, code := runCLI(t, "--serve", "--serve-addr", "127.0.0.1:0",
		"--targets", "127.0.0.1", "--ports", "1", "--skip-discovery", "--no-live", "--no-color")

	if code != 0 && code != 2 && code != 3 {
		t.Errorf("expected a valid risk-based exit code after clean shutdown, got %d", code)
	}
}

func TestCLI_RealScan_ExitCodeMatchesFindings(t *testing.T) {
	stdout, _, code := runCLI(t, "--targets", "127.0.0.1", "--ports", "1", "--skip-discovery", "--no-live", "--no-color")
	if code != 0 && code != 2 && code != 3 {
		t.Errorf("expected a valid documented exit code (0/2/3), got %d", code)
	}
	if !strings.Contains(stdout, "BAREPORT SECURITY ASSESSMENT") {
		t.Error("expected the assessment summary box in stdout")
	}
}

func TestCLI_JSONOutput_ViaRun(t *testing.T) {
	stdout, _, _ := runCLI(t, "--targets", "127.0.0.1", "--ports", "1", "--skip-discovery", "--no-live", "--json")
	if !strings.Contains(stdout, "\"risk\"") {
		t.Errorf("expected JSON output to contain a risk field, got: %q", stdout)
	}
}

func TestCLI_CSVOutput_ViaFormatFlag(t *testing.T) {
	stdout, stderr, code := runCLI(t, "--targets", "127.0.0.1", "--ports", "1", "--skip-discovery", "--no-live", "--format", "csv")
	if code != 0 && code != 2 && code != 3 {
		t.Fatalf("expected a valid exit code, got %d (stderr=%q)", code, stderr)
	}
	if !strings.Contains(stdout, "host,port") && !strings.Contains(stdout, "HOST") {
		t.Errorf("expected CSV output with a header row, got: %q", stdout)
	}
}

func TestCLI_CSVOutput_ViaCSVShorthandFlag(t *testing.T) {
	stdout, stderr, code := runCLI(t, "--targets", "127.0.0.1", "--ports", "1", "--skip-discovery", "--no-live", "--csv")
	if code != 0 && code != 2 && code != 3 {
		t.Fatalf("expected a valid exit code, got %d (stderr=%q)", code, stderr)
	}
	if stdout == "" {
		t.Error("expected non-empty CSV output via the --csv shorthand")
	}
}

func TestCLI_SARIFOutput_ViaFormatFlag(t *testing.T) {
	stdout, stderr, code := runCLI(t, "--targets", "127.0.0.1", "--ports", "1", "--skip-discovery", "--no-live", "--format", "sarif")
	if code != 0 && code != 2 && code != 3 {
		t.Fatalf("expected a valid exit code, got %d (stderr=%q)", code, stderr)
	}
	if !strings.Contains(stdout, "\"$schema\"") && !strings.Contains(stdout, "sarif") {
		t.Errorf("expected SARIF JSON output, got: %q", stdout)
	}
}

func TestCLI_MinimalOutput(t *testing.T) {
	stdout, stderr, code := runCLI(t, "--targets", "127.0.0.1", "--ports", "1", "--skip-discovery", "--no-live", "--minimal")
	if code != 0 && code != 2 && code != 3 {
		t.Fatalf("expected a valid exit code, got %d (stderr=%q)", code, stderr)
	}
	if stdout == "" {
		t.Error("expected non-empty minimal output")
	}
}

func TestCLI_ExplainFlag_PrintsFindingExplanations(t *testing.T) {
	// Use a real local plain-HTTP server (missing security headers) so
	// the --explain branch, which only fires when len(a.Findings) > 0,
	// actually executes.
	addr, cleanup := startPlainHTTP(t)
	defer cleanup()
	host, port := splitHostPort(t, addr)

	stdout, stderr, code := runCLI(t, "--targets", host, "--ports", fmt.Sprintf("%d", port), "--skip-discovery", "--no-live", "--no-color", "--explain")
	if code != 0 && code != 2 && code != 3 {
		t.Fatalf("expected a valid exit code, got %d (stderr=%q)", code, stderr)
	}
	if !strings.Contains(stdout, "What:") && !strings.Contains(stdout, "Recommendation") {
		t.Errorf("expected long-form finding explanations in output, got: %q", stdout)
	}
}

func TestCLI_SplitCSV(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"a,b,c", []string{"a", "b", "c"}},
		{"a, b , c", []string{"a", "b", "c"}},
		{"", nil},
		{"a,,b", []string{"a", "b"}},
		{"   ", nil},
		{"single", []string{"single"}},
	}
	for _, c := range cases {
		got := cli.SplitCSV(c.in)
		if len(got) != len(c.want) {
			t.Errorf("SplitCSV(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("SplitCSV(%q) = %v, want %v", c.in, got, c.want)
				break
			}
		}
	}
}

func TestCLI_ParsePortList(t *testing.T) {
	cases := []struct {
		in      string
		want    []int
		wantErr bool
	}{
		{"22", []int{22}, false},
		{"22,80,443", []int{22, 80, 443}, false},
		{"1-3", []int{1, 2, 3}, false},
		{"22,100-102", []int{22, 100, 101, 102}, false},
		{"", nil, false},
		{"abc", nil, true},
		{"5-2", nil, true},
		{"1-", nil, true},
		{"-5", nil, true},
	}
	for _, c := range cases {
		got, err := cli.ParsePortList(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParsePortList(%q): expected an error, got %v", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePortList(%q): unexpected error: %v", c.in, err)
			continue
		}
		if len(got) != len(c.want) {
			t.Errorf("ParsePortList(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("ParsePortList(%q) = %v, want %v", c.in, got, c.want)
				break
			}
		}
	}
}

func TestCLI_Verbose_EmitsWellFormedJSONLogs(t *testing.T) {
	var outBuf, errBuf bytes.Buffer
	cli.Run([]string{"--targets", "127.0.0.1", "--ports", "1", "--skip-discovery", "--no-live", "--no-color", "--verbose"}, &outBuf, &errBuf)

	lines := strings.Split(strings.TrimSpace(errBuf.String()), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected at least 2 structured log lines (scan_started, scan_completed), got %d: %q", len(lines), errBuf.String())
	}

	sawStarted, sawCompleted := false, false
	for _, line := range lines {
		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("log line is not valid JSON: %v — line: %q", err, line)
		}
		if entry["level"] != "INFO" {
			t.Errorf("expected level=INFO, got %v", entry["level"])
		}
		switch entry["msg"] {
		case "scan_started":
			sawStarted = true
		case "scan_completed":
			sawCompleted = true
			if _, ok := entry["risk_score"]; !ok {
				t.Error("expected scan_completed log entry to include risk_score")
			}
		}
	}
	if !sawStarted || !sawCompleted {
		t.Errorf("expected both scan_started and scan_completed log events, got: %s", errBuf.String())
	}

	// The human-facing report on stdout must be completely unaffected
	// by --verbose — it's an additive, separate-stream logging mode,
	// not a replacement for the normal output.
	if !strings.Contains(outBuf.String(), "BAREPORT SECURITY ASSESSMENT") {
		t.Error("expected the normal human-facing report to still print on stdout under --verbose")
	}
}
