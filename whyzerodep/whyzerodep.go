// Package whyzerodep holds the content behind the `bareport
// why-zero-dep` command: a plain-text explanation of what package each
// zero-dependency substitution replaces and what bareport uses
// instead. This is deliberately a small, static, hand-maintained list
// — not generated from STDLIB.md — but every entry here corresponds to
// a real, documented entry in STDLIB.md's substitution table, and
// updating one should mean updating the other. There is no build-time
// or test-time check enforcing that sync (that would need a markdown
// parser, which is more machinery than a short list justifies); it's
// a discipline this package's doc comment exists to name explicitly.
package whyzerodep

// Substitution is one row of the why-zero-dep report.
type Substitution struct {
	Category string
	Normally string
	Bareport string
}

// Substitutions is the full list shown by `bareport why-zero-dep`. See
// STDLIB.md's "Substitution table" for the fuller rationale behind
// each of these.
var Substitutions = []Substitution{
	{"CLI parsing", "spf13/cobra", "flag"},
	{"Interactive prompts", "manifoldco/promptui", "bufio.Scanner on stdin"},
	{"Terminal tables", "olekukonko/tablewriter", "text/tabwriter"},
	{"Progress display", "schollz/progressbar", "time.Ticker + raw ANSI redraw"},
	{"Terminal colors", "fatih/color", "raw ANSI escape sequences + os.Stdout TTY check"},
	{"Live TUI dashboard", "charmbracelet/bubbletea", "time.Ticker + raw ANSI cursor control"},
	{"HTTP client", "an HTTP client library (resty, req, ...)", "net/http"},
	{"TLS/certificate inspection", "a cert-parsing library", "crypto/tls + crypto/x509"},
	{"JSON encoding", "a JSON library (json-iterator, goccy/go-json, ...)", "encoding/json"},
	{"CSV encoding", "a CSV library (gocsv, ...)", "encoding/csv"},
	{"DNS lookups", "miekg/dns", "net.Resolver (LookupMX/LookupTXT/LookupHost/LookupAddr)"},
	{"Web dashboard / HTML report frontend", "a JS framework + build step", "html/template + embed, inline CSS/JS"},
	{"Worker pool / concurrency", "a worker-pool package (ants, pond, ...)", "sync.WaitGroup + buffered channels"},
	{"Cancellation", "a cancellation/lifecycle helper", "context.Context"},
	{"Test framework", "testify / ginkgo", "testing"},
	{"Baseline / drift diffing", "a diffing library (go-cmp, go-diff, ...)", "plain Go map/slice comparisons in report.CompareAssessments"},
	{"SARIF output", "a SARIF SDK", "encoding/json against the SARIF 2.1.0 schema directly"},
	{"Structured logging", "a structured-logging library (zap, logrus, ...)", "log/slog"},
	{"Fuzzing", "a fuzzing framework (go-fuzz, ...)", "testing (native Go fuzzing, e.g. FuzzClassifyBanner)"},
}

// Header is printed above the substitution list by `bareport why-zero-dep`.
const Header = "BAREPORT ZERO-DEPENDENCY REPORT"
