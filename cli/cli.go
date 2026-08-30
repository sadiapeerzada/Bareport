// Package cli implements bareport's entire command-line surface: flag
// parsing, subcommands (diff, why-zero-dep), and scan orchestration
// output. It exists as a separate, importable package — rather than
// living directly in package main — specifically so it's unit
// testable: package main is structurally excluded from Go's coverage
// tooling (`go test -coverpkg` can't attribute coverage to a package
// that test code can't import), so anything that stayed in main.go
// would look permanently untested in a coverage report no matter how
// thoroughly the integration test lab (integration/main.go) actually
// exercises it black-box.
//
// The exported entry point is Run(args, stdout, stderr) — everything
// that used to write directly to os.Stdout/os.Stderr now writes to the
// passed-in io.Writers instead, so tests/cli_test.go can capture and
// assert on real output without touching the process's actual stdio.
// main.go itself is now just:
//
//	func main() { os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr)) }
package cli

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"bareport/config"
	"bareport/report"
	"bareport/scanner"
	"bareport/selfaudit"
	"bareport/web"
	"bareport/whyzerodep"
)

// Run is bareport's entire program logic, parameterized over argv and
// the two output streams so it's callable from both main() (with the
// real os.Args/os.Stdout/os.Stderr) and from tests (with a fake args
// slice and bytes.Buffers). Returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	cfg, mode, err := parseFlags(args, stdout)
	if err != nil {
		fmt.Fprintln(stderr, "bareport:", err)
		return 1 // tool/usage error — see risk.Result.ExitCode's doc comment for the full scheme
	}
	if mode == modeHelp {
		return 0
	}

	// Ctrl+C handling: signal.NotifyContext gives us a context that's
	// cancelled the moment SIGINT/SIGTERM arrives, which every scanner
	// worker and the web server already select on — this is the single
	// place cancellation is wired in, everything downstream just reacts
	// to ctx.Done(). This is real OS signal wiring, not something a unit
	// test exercises directly (there's no meaningful way to unit-test
	// "did the OS deliver a signal" without actually sending one to the
	// test process) — signal-driven cancellation is instead verified by
	// manual stress testing (see README) and is inherently a
	// process-level, not a function-level, concern.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch mode {
	case modeDiff:
		return runDiff(cfg, stdout, stderr)
	case modeWhyZeroDep:
		return runWhyZeroDep(stdout)
	case modeVerifyZeroDep:
		return runVerifyZeroDep(stdout)
	case modeWatch:
		return runWatch(ctx, cfg, stdout, stderr)
	default:
		return runScan(ctx, cfg, stdout, stderr)
	}
}

func runScan(ctx context.Context, cfg config.Config, stdout, stderr io.Writer) int {
	// --verbose: structured (log/slog, JSON) scan-lifecycle logging to
	// stderr, entirely separate from the human-facing report on
	// stdout — for scripting/debugging use, not a replacement for the
	// table/dashboard output, which is unconditionally unchanged. Real
	// stdlib structured logging (log/slog, stdlib since Go 1.21) —
	// see STDLIB.md for the explicit logrus/zap substitution rationale.
	var logger *slog.Logger
	if cfg.Verbose {
		logger = slog.New(slog.NewJSONHandler(stderr, nil))
	}
	logEvent := func(msg string, args ...any) {
		if logger != nil {
			logger.Info(msg, args...)
		}
	}

	logEvent("scan_started", "targets", cfg.Targets, "profile", cfg.Profile, "workers", cfg.Workers)

	// Live terminal dashboard: only makes sense when a human is
	// actually watching a real terminal in real time — disabled for
	// --serve (the web dashboard is the live view there), for
	// non-table output formats (JSON/CSV must stay clean for piping),
	// when stdout isn't a TTY (piped/redirected), and when the user
	// opts out via --no-live. report.IsTTY takes an *os.File; a
	// bytes.Buffer passed in tests never satisfies that type
	// assertion below, so this path is simply inert (never fires)
	// under test, exactly as intended — no live-dashboard goroutine
	// starts up during a unit test run.
	var live *report.LiveDashboard
	if f, ok := stdout.(*os.File); ok && !cfg.Serve && cfg.OutputFormat == "table" && !cfg.NoLive && report.IsTTY(f) {
		live = report.NewLiveDashboard(stdout)
		live.Start()
	}

	var rep *scanner.Report
	var err error
	if live != nil {
		rep, err = scanner.Run(ctx, cfg, live.Update)
		live.Stop()
	} else {
		rep, err = scanner.Run(ctx, cfg)
	}

	if err != nil && rep == nil {
		logEvent("scan_failed", "error", err.Error())
		fmt.Fprintln(stderr, "bareport: scan failed:", err)
		return 1 // tool/scan error — see risk.Result.ExitCode's doc comment for the full scheme
	}
	if err != nil {
		logEvent("scan_interrupted", "error", err.Error())
		fmt.Fprintln(stderr, "bareport: scan interrupted:", err)
		// fall through: still report whatever partial results we have,
		// and still exit based on findings in that partial data — being
		// interrupted mid-scan isn't a tool error, it's a user action.
	}

	assessment := report.BuildAssessment(rep, cfg.Targets, cfg.Profile)
	logEvent("scan_completed",
		"duration_ms", rep.Duration.Milliseconds(),
		"hosts_scanned", assessment.Summary.HostsScanned,
		"ports_open", assessment.Summary.PortsOpen,
		"findings", len(assessment.Findings),
		"risk_score", assessment.Risk.Score,
		"risk_level", assessment.Risk.Level,
	)

	if cfg.HTMLPath != "" {
		if werr := writeHTMLReport(cfg.HTMLPath, assessment, stderr); werr != nil {
			fmt.Fprintln(stderr, "bareport:", werr)
			return 1
		}
	}
	if cfg.SavePath != "" {
		if werr := writeSavedAssessment(cfg.SavePath, assessment, stderr); werr != nil {
			fmt.Fprintln(stderr, "bareport:", werr)
			return 1
		}
	}

	if cfg.Serve {
		srv, werr := web.New(assessment, nil)
		if werr != nil {
			fmt.Fprintln(stderr, "bareport: dashboard init failed:", werr)
			return 1
		}
		addr := cfg.ServeAddr
		if addr == "" {
			addr = "127.0.0.1:0"
		}
		if serr := srv.Serve(ctx, addr); serr != nil {
			fmt.Fprintln(stderr, "bareport: dashboard error:", serr)
			return 1
		}
		return assessment.Risk.ExitCode()
	}

	if werr := writeOutput(assessment, cfg, stdout); werr != nil {
		fmt.Fprintln(stderr, "bareport:", werr)
		return 1
	}

	return assessment.Risk.ExitCode()
}

func writeHTMLReport(path string, a *report.SecurityAssessment, stderr io.Writer) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating HTML report %s: %w", path, err)
	}
	defer f.Close()
	if err := report.WriteHTML(f, a); err != nil {
		return err
	}
	fmt.Fprintf(stderr, "wrote HTML security report to %s\n", path)
	return nil
}

func writeSavedAssessment(path string, a *report.SecurityAssessment, stderr io.Writer) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	defer f.Close()
	if err := report.WriteAssessmentJSON(f, a); err != nil {
		return err
	}
	fmt.Fprintf(stderr, "saved assessment to %s\n", path)
	return nil
}

func writeOutput(a *report.SecurityAssessment, cfg config.Config, stdout io.Writer) error {
	switch {
	case cfg.OutputFormat == "json":
		return report.WriteAssessmentJSON(stdout, a)
	case cfg.OutputFormat == "csv":
		return report.WriteCSV(stdout, &a.Report)
	case cfg.OutputFormat == "sarif":
		return report.WriteSARIF(stdout, a)
	case cfg.Minimal:
		return report.WriteMinimal(stdout, a)
	default:
		f, isFile := stdout.(*os.File)
		useColor := !cfg.NoColor && isFile && report.IsTTY(f)
		if err := report.WriteTable(stdout, &a.Report, useColor); err != nil {
			return err
		}
		fmt.Fprintln(stdout)
		if err := report.WriteAssessmentSummary(stdout, a, useColor); err != nil {
			return err
		}
		if cfg.Explain && len(a.Findings) > 0 {
			fmt.Fprintln(stdout)
			return report.WriteFindingExplanations(stdout, a)
		}
		return nil
	}
}

// runDiff implements `bareport diff <baseline.json> <current.json>`:
// load two previously-saved assessment JSON files (from a prior
// `bareport --json > file` or `--save file` run) and print the
// security posture drift between them — new/closed ports, new/removed
// services, new/resolved findings, TLS certificate changes, and the
// risk score delta (baseline/drift detection).
func runDiff(cfg config.Config, stdout, stderr io.Writer) int {
	if len(cfg.Targets) != 2 {
		fmt.Fprintln(stderr, "bareport diff: usage: bareport diff <baseline.json> <current.json>")
		return 1
	}
	before, err := loadAssessmentFile(cfg.Targets[0])
	if err != nil {
		fmt.Fprintln(stderr, "bareport:", err)
		return 1
	}
	after, err := loadAssessmentFile(cfg.Targets[1])
	if err != nil {
		fmt.Fprintln(stderr, "bareport:", err)
		return 1
	}

	d := report.CompareAssessments(before, after)
	if err := report.WriteSecurityDrift(stdout, d); err != nil {
		fmt.Fprintln(stderr, "bareport:", err)
		return 1
	}
	return 0
}

func loadAssessmentFile(path string) (*report.SecurityAssessment, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()
	return report.LoadAssessment(f)
}

// runWhyZeroDep implements `bareport why-zero-dep`: prints the
// dependency-substitution list from the whyzerodep package, which is
// kept in sync (by hand — see that package's doc comment) with
// STDLIB.md's fuller substitution table.
func runWhyZeroDep(stdout io.Writer) int {
	fmt.Fprintln(stdout, whyzerodep.Header)
	fmt.Fprintln(stdout, strings.Repeat("─", len(whyzerodep.Header)))
	fmt.Fprintln(stdout)
	for _, s := range whyzerodep.Substitutions {
		fmt.Fprintln(stdout, s.Category)
		fmt.Fprintln(stdout, "Normally: "+s.Normally)
		fmt.Fprintln(stdout, "Bareport: "+s.Bareport)
		fmt.Fprintln(stdout)
	}
	fmt.Fprintln(stdout, "Full rationale for each substitution: STDLIB.md")
	return 0
}

// runVerifyZeroDep implements `bareport --verify-zero-dep`: the
// runtime counterpart to `make deps-proof`. deps-proof proves zero
// third-party dependencies at build time (go list -m all); this proves
// it at run time, every time the binary executes, by cross-checking
// bareport's own import graph (captured at generate time — see
// selfaudit's doc comment) against the real Go standard library.
// Exits 0 if clean, 1 if anything outside stdlib is found — deliberately
// separate from the scan risk-based exit codes (see risk.Result.ExitCode's
// doc comment), since this isn't a scan.
func runVerifyZeroDep(stdout io.Writer) int {
	r := selfaudit.Verify()

	fmt.Fprintln(stdout, "bareport zero-dependency self-audit")
	fmt.Fprintln(stdout)
	fmt.Fprintf(stdout, "  go.mod:               module %s, go %s, %d require lines\n", r.ModulePath, r.GoDirective, r.RequireLineCount)
	fmt.Fprintf(stdout, "  imports walked:       %d\n", r.ImportsWalked)
	fmt.Fprintf(stdout, "  outside stdlib:       %d\n", len(r.OutsideStdlib))
	fmt.Fprintln(stdout)

	if r.Verified() {
		fmt.Fprintln(stdout, "VERIFIED — zero third-party runtime dependencies")
		return 0
	}

	fmt.Fprintln(stdout, "FAILED — found import(s) outside the standard library:")
	for _, v := range r.OutsideStdlib {
		fmt.Fprintf(stdout, "  - %s\n", v)
	}
	return 1
}

// runWatch implements `bareport --watch`: continuous mode. Re-scans
// cfg.Targets every cfg.WatchInterval, diffing each scan's assessment
// against the previous one (report.CompareAssessments, the same
// engine `bareport diff` uses on two saved files) and printing drift
// as it happens, instead of requiring two manual --save runs and a
// separate `bareport diff` invocation afterward. Runs until ctx is
// canceled (Ctrl+C — see Run's signal.NotifyContext wiring, the same
// cancellation path runScan uses).
func runWatch(ctx context.Context, cfg config.Config, stdout, stderr io.Writer) int {
	var logger *slog.Logger
	if cfg.Verbose {
		logger = slog.New(slog.NewJSONHandler(stderr, nil))
	}
	logEvent := func(msg string, args ...any) {
		if logger != nil {
			logger.Info(msg, args...)
		}
	}

	fmt.Fprintf(stdout, "bareport watch: re-scanning every %s (Ctrl+C to stop)\n\n", cfg.WatchInterval)
	logEvent("watch_started", "targets", cfg.Targets, "interval", cfg.WatchInterval.String())

	var previous *report.SecurityAssessment
	iteration := 0
	exitCode := 0

	for {
		iteration++
		logEvent("watch_scan_started", "iteration", iteration)

		rep, err := scanner.Run(ctx, cfg)
		if err != nil {
			if ctx.Err() != nil {
				// Canceled mid-scan (Ctrl+C) -- a clean stop, not a
				// failure; fall through to the same "stopped" exit
				// below rather than reporting an error.
				fmt.Fprintln(stdout, "bareport watch: stopped")
				return exitCode
			}
			if rep == nil {
				logEvent("watch_scan_failed", "iteration", iteration, "error", err.Error())
				fmt.Fprintln(stderr, "bareport watch: scan failed:", err)
				return 1
			}
			// Non-cancellation error but partial results exist --
			// same fallthrough runScan uses: report what we have.
			logEvent("watch_scan_interrupted", "iteration", iteration, "error", err.Error())
		}

		assessment := report.BuildAssessment(rep, cfg.Targets, cfg.Profile)
		exitCode = assessment.Risk.ExitCode()
		now := time.Now().Format("15:04:05")

		if previous == nil {
			fmt.Fprintf(stdout, "[%s] initial scan:\n\n", now)
			if err := report.WriteTable(stdout, rep, !cfg.NoColor); err != nil {
				fmt.Fprintln(stderr, "bareport watch:", err)
			}
			if err := report.WriteAssessmentSummary(stdout, assessment, !cfg.NoColor); err != nil {
				fmt.Fprintln(stderr, "bareport watch:", err)
			}
		} else {
			drift := report.CompareAssessments(previous, assessment)
			if drift.HasChanges() {
				fmt.Fprintf(stdout, "[%s] re-scan #%d — drift detected:\n\n", now, iteration)
				if err := report.WriteSecurityDrift(stdout, drift); err != nil {
					fmt.Fprintln(stderr, "bareport watch:", err)
				}
				logEvent("watch_drift_detected", "iteration", iteration)
			} else {
				fmt.Fprintf(stdout, "[%s] re-scan #%d — no changes (risk %d/100, %s)\n",
					now, iteration, assessment.Risk.Score, assessment.Risk.Level)
			}
		}
		fmt.Fprintln(stdout)

		previous = assessment
		logEvent("watch_scan_completed", "iteration", iteration, "risk_score", assessment.Risk.Score)

		select {
		case <-ctx.Done():
			fmt.Fprintln(stdout, "bareport watch: stopped")
			return exitCode
		case <-time.After(cfg.WatchInterval):
		}
	}
}

type runMode int

const (
	modeScan runMode = iota
	modeDiff
	modeWhyZeroDep
	modeVerifyZeroDep
	modeWatch
	modeHelp
)

// parseFlags builds a config.Config from CLI flags (and, if --config is
// given, overlays a saved JSON profile). Using the standard "flag"
// package rather than a third-party flag/cobra library is itself part
// of the zero-dependency constraint — flag.FlagSet's slightly more
// verbose API (no built-in subcommands) is why `diff` and
// `why-zero-dep` are handled as special first-argument cases below
// instead of flag's own subcommand sugar, which doesn't exist in
// stdlib.
//
// stdout is threaded through only so --help's usage text (which
// flag.FlagSet writes itself) and --save-config's confirmation message
// go to the right place under test; it's the same parameter Run()
// received.
func parseFlags(args []string, stdout io.Writer) (config.Config, runMode, error) {
	if len(args) > 0 && args[0] == "diff" {
		if len(args) != 3 {
			return config.Config{}, modeHelp, fmt.Errorf("usage: bareport diff <baseline.json> <current.json>")
		}
		return config.Config{Targets: []string{args[1], args[2]}}, modeDiff, nil
	}
	if len(args) > 0 && args[0] == "why-zero-dep" {
		return config.Config{}, modeWhyZeroDep, nil
	}

	fs := flag.NewFlagSet("bareport", flag.ContinueOnError)
	fs.SetOutput(stdout)

	def := config.Default()

	targets := fs.String("targets", "", "comma-separated hosts, CIDR ranges, or @file")
	ports := fs.String("ports", "", "comma-separated ports / ranges, e.g. 22,80,8000-8100")
	preset := fs.String("preset", def.PortPreset, "port preset: top100 | top1000 (ignored if --ports set)")
	udpPorts := fs.String("udp-ports", "", "comma-separated UDP ports to probe")
	workers := fs.Int("workers", def.Workers, "concurrent worker goroutines")
	connectTimeout := fs.Duration("timeout", def.ConnectTimeout, "per-connection timeout")
	bannerTimeout := fs.Duration("banner-timeout", def.BannerTimeout, "banner read timeout")
	dnsTimeout := fs.Duration("dns-timeout", def.DNSTimeout, "DNS lookup timeout (bounds forward/MX/TXT/DMARC/reverse lookups)")
	skipDiscovery := fs.Bool("skip-discovery", false, "scan every host without a liveness pre-check")
	// These five flag defaults are derived from def (config.Default()),
	// same as preset/workers/timeouts above, rather than hardcoded —
	// cfg.DoDNS/DoBanners/DoFinger/DoTLS/DoHTTP below are set
	// unconditionally from these flag values every run, so a hardcoded
	// literal here would silently override whatever config.Default()
	// resolves to for any invocation that doesn't pass the flag
	// explicitly (which is what happened when Default() switched to
	// deriving these fields from ApplyProfile("security") but these
	// literals weren't updated to match).
	doDNS := fs.Bool("dns", def.DoDNS, "run DNS reconnaissance (MX/TXT/SPF/DMARC/reverse)")
	noBanners := fs.Bool("no-banners", !def.DoBanners, "disable banner grabbing")
	noFinger := fs.Bool("no-fingerprint", !def.DoFinger, "disable TTL-based OS fingerprinting")
	noTLS := fs.Bool("no-tls", !def.DoTLS, "disable TLS/certificate inspection")
	noHTTP := fs.Bool("no-http", !def.DoHTTP, "disable HTTP header audit")
	outFormat := fs.String("format", def.OutputFormat, "output format: table | json | csv | sarif")
	jsonOut := fs.Bool("json", false, "shorthand for --format=json")
	csvOut := fs.Bool("csv", false, "shorthand for --format=csv")
	noColor := fs.Bool("no-color", false, "disable ANSI color in table output")
	noLive := fs.Bool("no-live", false, "disable the live in-place terminal progress dashboard")
	localNetwork := fs.Bool("local-network", false, "auto-detect and scan the local subnet (via net.Interfaces()), zero target configuration needed")
	serve := fs.Bool("serve", false, "launch the local web dashboard instead of printing a report")
	serveAddr := fs.String("serve-addr", "", "dashboard listen address, e.g. 127.0.0.1:8080 (default: random port)")
	configPath := fs.String("config", "", "load a saved JSON scan profile")
	saveConfig := fs.String("save-config", "", "save the resolved config to this path and exit")
	profile := fs.String("profile", "", "scan profile: quick | security | full (overrides individual scanner flags)")
	htmlPath := fs.String("html", "", "write a self-contained HTML security report to this path")
	savePath := fs.String("save", "", "write the assessment JSON to this path (in addition to --format output) — for later use with the diff subcommand")
	minimal := fs.Bool("minimal", false, "compact output: target, open ports, risk level, finding count — nothing else")
	explain := fs.Bool("explain", false, "print the long-form What/Evidence/Recommendation explanation for every finding")
	verbose := fs.Bool("verbose", false, "emit structured JSON scan-lifecycle logs (log/slog) to stderr, separate from the human-facing report on stdout")
	verifyZeroDep := fs.Bool("verify-zero-dep", false, "run the runtime zero-dependency self-audit and exit (see selfaudit package)")
	watch := fs.Bool("watch", false, "continuous mode: re-scan every --interval, printing drift against the previous scan (Ctrl+C to stop)")
	watchInterval := fs.Duration("interval", def.WatchInterval, "re-scan interval for --watch")
	adminPaths := fs.String("admin-paths", "", "comma-separated paths to probe for an unauthenticated admin endpoint, e.g. admin,manage (opt-in: off by default, since an always-on guess-common-paths probe would misfire against any server whose catch-all route answers every path with 200)")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			// -h/--help isn't a usage error — flag.FlagSet has already
			// printed the usage text itself; returning nil here (not
			// err) means Run()'s error path is skipped and modeHelp's
			// `return 0` in Run() applies, so `bareport --help` exits 0
			// like a normal, successful invocation rather than looking
			// like a failure to a CI script checking $?.
			return config.Config{}, modeHelp, nil
		}
		return config.Config{}, modeHelp, err
	}

	// --verify-zero-dep exits immediately after flag parsing, before
	// any targets/config resolution below — it's a self-check about
	// the binary itself, not a scan, so none of the target-required
	// logic further down should apply to it.
	if *verifyZeroDep {
		return config.Config{}, modeVerifyZeroDep, nil
	}

	cfg := def
	if *configPath != "" {
		loaded, err := config.Load(*configPath, def)
		if err != nil {
			return config.Config{}, modeHelp, err
		}
		cfg = loaded
	}

	if *targets != "" {
		cfg.Targets = SplitCSV(*targets)
	}
	if *ports != "" {
		parsed, err := ParsePortList(*ports)
		if err != nil {
			return config.Config{}, modeHelp, fmt.Errorf("parsing --ports: %w", err)
		}
		cfg.Ports = parsed
	}
	cfg.PortPreset = *preset
	if *udpPorts != "" {
		parsed, err := ParsePortList(*udpPorts)
		if err != nil {
			return config.Config{}, modeHelp, fmt.Errorf("parsing --udp-ports: %w", err)
		}
		cfg.UDPPorts = parsed
	}
	cfg.Workers = *workers
	cfg.ConnectTimeout = *connectTimeout
	cfg.BannerTimeout = *bannerTimeout
	cfg.DNSTimeout = *dnsTimeout
	cfg.SkipDiscovery = *skipDiscovery
	cfg.DoDNS = *doDNS
	cfg.DoBanners = !*noBanners
	cfg.DoFinger = !*noFinger
	cfg.DoTLS = !*noTLS
	cfg.DoHTTP = !*noHTTP
	cfg.OutputFormat = *outFormat
	if *jsonOut {
		cfg.OutputFormat = "json"
	}
	if *csvOut {
		cfg.OutputFormat = "csv"
	}
	cfg.NoColor = *noColor
	cfg.NoLive = *noLive
	cfg.Serve = *serve
	cfg.ServeAddr = *serveAddr
	cfg.HTMLPath = *htmlPath
	cfg.SavePath = *savePath
	cfg.Minimal = *minimal
	cfg.Explain = *explain
	cfg.Verbose = *verbose
	cfg.Watch = *watch
	cfg.WatchInterval = *watchInterval
	if *adminPaths != "" {
		cfg.AdminPaths = SplitCSV(*adminPaths)
	}

	// --profile applies AFTER the individual scanner flags above so it
	// can override their defaults, but a profile only sets the specific
	// fields documented in config.ApplyProfile — it never touches
	// cfg.Targets, output format, or any of the flags handled below.
	if *profile != "" {
		applied, err := config.ApplyProfile(cfg, *profile)
		if err != nil {
			return config.Config{}, modeHelp, err
		}
		cfg = applied
	}

	// --local-network (CONVENIENCE FEATURE): auto-detect the local
	// subnet via net.Interfaces()/net.InterfaceAddrs() and scan it with
	// zero target configuration, overriding whatever --targets/--config
	// supplied — the flag is an explicit "scan my LAN" request, so it
	// should win rather than merge silently with unrelated targets.
	if *localNetwork {
		subnet, err := scanner.LocalSubnet()
		if err != nil {
			return config.Config{}, modeHelp, fmt.Errorf("--local-network: %w", err)
		}
		cfg.Targets = []string{subnet}
		fmt.Fprintf(stdout, "--local-network: scanning auto-detected subnet %s\n", subnet)
	}

	// Minimal interactive mode (replaces a promptui-style dependency —
	// see STDLIB.md): if no targets were resolved by any of the above
	// and we're not launching the dashboard, and stdin looks like an
	// actual interactive terminal (not piped/redirected, which matters
	// for CI and scripted use — those should fail fast with the usage
	// error below, not hang waiting for input), ask for one target via
	// a plain bufio.Scanner read rather than erroring out immediately.
	if len(cfg.Targets) == 0 && !*serve {
		if report.IsTTY(os.Stdin) {
			target, perr := promptForTarget(os.Stdin, stdout)
			if perr == nil && target != "" {
				cfg.Targets = []string{target}
			}
		}
	}

	if len(cfg.Targets) == 0 && !*serve {
		return config.Config{}, modeHelp, fmt.Errorf("no targets given; use --targets host1,host2,@hostfile.txt, --local-network, or run interactively")
	}

	if *saveConfig != "" {
		if err := config.Save(*saveConfig, cfg); err != nil {
			return config.Config{}, modeHelp, err
		}
		fmt.Fprintf(stdout, "saved config profile to %s\n", *saveConfig)
		return cfg, modeHelp, nil
	}

	if cfg.Watch {
		if cfg.Serve {
			return config.Config{}, modeHelp, fmt.Errorf("--watch and --serve are mutually exclusive (watch is for the terminal/CI; --serve already has its own live dashboard)")
		}
		return cfg, modeWatch, nil
	}

	return cfg, modeScan, nil
}

// promptForTarget implements a minimal interactive mode — the
// zero-dependency substitute for a prompt library like promptui (see
// STDLIB.md): a single bufio.Scanner read from stdin. It's deliberately
// not a full interactive menu (no arrow-key navigation, no validation
// loop) — just enough to let someone run `bareport` with no arguments
// from a real terminal and be asked what to scan, rather than being
// bounced straight to a usage error.
func promptForTarget(in io.Reader, out io.Writer) (string, error) {
	fmt.Fprint(out, "No target specified. Enter a host, IP, or CIDR to scan: ")
	sc := bufio.NewScanner(in)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return "", fmt.Errorf("reading target: %w", err)
		}
		return "", nil // EOF with nothing entered
	}
	return strings.TrimSpace(sc.Text()), nil
}

// SplitCSV splits a comma-separated flag value, trimming whitespace
// and dropping empty entries. Exported specifically so
// tests/cli_test.go can exercise its edge cases directly — the same
// reasoning as scanner.HasSPFRecord's export in scanner/dns.go: it's a
// pure function with no dependency on the rest of this package's
// state.
func SplitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ParsePortList accepts a comma-separated mix of single ports ("22")
// and ranges ("8000-8100"). Exported for the same reason as SplitCSV.
func ParsePortList(s string) ([]int, error) {
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			lo, err := strconv.Atoi(strings.TrimSpace(bounds[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid range %q: %w", part, err)
			}
			hi, err := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid range %q: %w", part, err)
			}
			if lo > hi {
				return nil, fmt.Errorf("invalid range %q: start > end", part)
			}
			for p := lo; p <= hi; p++ {
				out = append(out, p)
			}
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", part, err)
		}
		out = append(out, p)
	}
	return out, nil
}
