# STDLIB.md — stdlib-for-package substitutions

This file exists for two audiences: the Zero Dependency judges (this
top section — a scannable list of what a third-party package would
normally have been used for, and what stdlib does instead), and future
me during the actual hackathon rebuild (the "why each package is used
where" narrative further down, which is the part worth re-reading).

Written incrementally as each substitution was made, not reconstructed
after the fact — the ordering below roughly follows build order.

## Substitution table (19 entries, Package Killer bonus target)

| # | Would normally reach for | stdlib substitute | Rationale |
|---|---|---|---|
| 1 | **`fatih/color`** — the de facto standard Go terminal-color package. Per pkg.go.dev (checked live while writing this file, https://pkg.go.dev/github.com/fatih/color), it is imported by **27,995** other packages — used for exactly the colorized severity/state output this tool needs | `report/color.go`: raw ANSI escape codes (`"\033[31m"` etc.) + a hand-rolled TTY check (`os.Stdout.Stat()`, testing `info.Mode() & os.ModeCharDevice`) | `fatih/color` itself is a thin wrapper around ANSI codes and an isatty check — both trivial to inline directly, and inlining removes the dependency entirely with no loss of functionality for our fixed severity/state palette. |
| 2 | An HTTP client library (e.g. `go-resty/resty`, `imroc/req`) for the HTTP fingerprinting/header-audit fetches | `net/http` — custom `http.Client` with a `CheckRedirect` hook (`scanner/http.go`) | stdlib's `net/http` already has everything a recon tool needs (redirect-chain capture, custom `Transport.TLSClientConfig`, per-method requests); third-party HTTP clients mainly add convenience sugar this codebase doesn't need. |
| 3 | A certificate-parsing package (e.g. `google/certificate-transparency-go`'s x509 helpers, or `smallstep/certificates`' cert utils) for reading Subject/Issuer/SAN/expiry off a live TLS connection | `crypto/tls` + `crypto/x509` (`scanner/tls.go`) | stdlib's `x509.Certificate` struct already exposes every field this tool reports (`NotAfter`, `Subject`, `Issuer`, `DNSNames`), and `tls.Client(...).HandshakeContext` does the live handshake — no parsing library needed on top. |
| 4 | A JSON library (e.g. `json-iterator/go`, `goccy/go-json`) for report serialization | `encoding/json` (`report/json.go`, `config/config.go`, `report/diff.go`) | Those libraries exist mainly for marginal performance gains at very high throughput; a scan report serialized once per run has no such requirement, so stdlib's `encoding/json` — with struct tags already on every type — is strictly sufficient. |
| 5 | A frontend build step (webpack/vite bundling a JS framework's compiled output) for the dashboard UI | `html/template` + `embed` (`web/server.go`, `web/templates/dashboard.html`, `web/static/style.css`) | The dashboard is server-rendered HTML with a small amount of inline vanilla JS for sort/filter; `go:embed` bakes the template and stylesheet into the compiled binary, so there's no separate build pipeline or JS runtime dependency at all — one `go build` produces the whole artifact. |
| 6 | A table-formatting/pretty-print package (e.g. `olekukonko/tablewriter`) for the terminal report | `text/tabwriter` (`report/table.go`) | `text/tabwriter` does exactly one thing — align tab-separated columns — which is exactly what the table report needs; a full-featured table library's borders/styling options go unused here. |
| 7 | A cancellation/lifecycle library (e.g. patterns from `golang.org/x/sync/errgroup`, explicitly excluded per the rules anyway) for coordinating scan cancellation across goroutines | `context` (used throughout `scanner/`, wired to OS signals via `signal.NotifyContext` in `main.go`) | `context.Context` is the stdlib primitive third-party cancellation helpers are themselves built on; wiring `ctx.Done()` checks directly into each worker loop needed no additional abstraction on top. |
| 8 | A worker-pool package (e.g. `panjf2000/ants`, `alitto/pond`) for bounding scan concurrency | `sync.WaitGroup` + buffered channels (`scanner/tcp.go`, `udp.go`, `discovery.go`) | A worker pool is fundamentally "N goroutines pulling from a channel until it's closed" — a few lines of `sync` + `chan job`, not a dependency; the third-party packages mainly add pool-resizing and metrics this tool doesn't need. |
| 9 | A CSV library (e.g. `gocarina/gocsv`) for the CSV report export | `encoding/csv` (`report/csv.go`) | stdlib's `csv.Writer` already handles quoting/escaping commas and quotes inside finding messages correctly — the exact problem a CSV library exists to solve — so there's nothing left for a third-party package to add. |
| 10 | A DNS library (e.g. `miekg/dns` — per pkg.go.dev, checked live while writing this file, imported by **16,234** other packages) for MX/TXT/SPF/DMARC lookups | `net.Resolver`'s `LookupMX`/`LookupTXT`/`LookupHost`/`LookupAddr` (`scanner/dns.go`) | `miekg/dns` earns its keep when you need to construct raw DNS packets or query non-standard record types; this tool only needs standard record lookups the OS resolver already exposes through `net`, so reaching for a full DNS protocol implementation would be overkill. |
| 11 | A test framework (e.g. `testify`, `ginkgo`/`gomega`) for assertions and test structure | `testing` (`tests/scanner_test.go`, `tests/scanner_bench_test.go`) | stdlib's `testing` package's plain `if got != want { t.Errorf(...) }` style is entirely sufficient for this project's assertion needs, and `testing.B` covers the benchmark requirement natively — no assertion-library sugar required. |
| 12 | A flag/CLI framework (e.g. `spf13/cobra` — per pkg.go.dev, checked live while writing this file (https://pkg.go.dev/github.com/spf13/cobra), imported by **195,884** other packages, making it one of the highest-importer-count packages in the entire Go ecosystem; it's the framework behind kubectl, Hugo, and the GitHub CLI, `urfave/cli`) for the command-line interface | `flag` (`main.go`) | stdlib `flag.FlagSet` covers every flag this tool needs; the one place a framework's subcommand sugar would have helped (the `diff` subcommand) is instead handled with a two-line special case on `os.Args[0]` — a worthwhile trade for zero dependencies. |
| 13 | **`charmbracelet/bubbletea`** — the standard Go TUI framework, with roughly 11,700 known importers on pkg.go.dev (checked while writing this file) — used for exactly the kind of live-updating terminal progress display a scan tool wants | `report/live.go`: a `LiveDashboard` driven by a `time.Ticker`, redrawing in place with raw ANSI cursor-control codes (`\033[2K` erase-line, `\033[<n>A` cursor-up) | Bubbletea's Elm-architecture model/update/view loop earns its keep for genuinely interactive TUIs (key/mouse input, multiple screens, widget composition); a five-line "hosts/ports/findings/elapsed, updating in place" readout needs none of that — it needs exactly the redraw primitive bubbletea itself is built on top of, used directly. |
| 14 | **`schollz/progressbar`** — per pkg.go.dev, checked live while writing this file, imported by **2,443** other packages; a widely-used, actively-maintained Go progress-bar package (packaged for Debian/Ubuntu, used by tools like `croc`) | `time.Ticker`-driven redraw inside the same `report/live.go` `LiveDashboard` from #13 — the ticker decouples redraw rate from event rate exactly the way a progress-bar library's internal renderer does | A progress bar is fundamentally "track a count, redraw a bar of characters proportional to it, on a timer so fast updates don't flood the terminal." `LiveDashboard` implements exactly that loop directly against `os.Stdout`, sized for this tool's specific four-line "hosts/ports/findings/elapsed" shape rather than a generic bar widget. |
| 15 | **`manifoldco/promptui`** — per pkg.go.dev, checked live while writing this file, imported by **3,547** other packages; commonly paired with `spf13/cobra` (per its own documentation) for CLIs that need to ask the user a question | `bufio.Scanner` reading one line from stdin (`main.go`'s `promptForTarget`), gated on `report.IsTTY(os.Stdin)` so it never fires in a non-interactive/CI context | promptui's real value is rich prompt types (masked input, live-validated input, arrow-key select menus with search/pagination); this tool only ever needs to ask one plain question ("what host?") when no `--targets` was given, which a single `bufio.Scanner.Scan()` call answers completely. |
| 16 | A structural-diff library (e.g. `google/go-cmp`, `r3labs/diff`) for the baseline/drift comparison between two scans | `report/diff.go` and `report/security_drift.go`: plain Go maps keyed by host:port (or by finding ID), built once per side, then compared with ordinary map lookups (`if _, existed := before[key]; !existed { ... }`) | A generic structural-diff library reflects over arbitrary struct shapes to find what changed, which is real, non-trivial machinery — worth it when you don't know the shape of what you're diffing ahead of time. Bareport always knows exactly what it's comparing (two `SecurityAssessment`s with a fixed, known shape: ports, services, findings, risk score, TLS certs), so a handful of purpose-built map comparisons — one per category — replace it entirely, and read more clearly at each call site than a generic `cmp.Diff()` call would. |
| 17 | A SARIF SDK/library (e.g. `owenrumney/go-sarif`) for CI code-scanning-compatible output | `report/sarif.go`: hand-built structs mirroring the subset of the SARIF 2.1.0 object model bareport actually populates (`$schema`, `version`, `runs[].tool.driver.rules`, `runs[].results`), marshaled with `encoding/json` | A SARIF SDK's main value is a complete, spec-covering object model plus validation helpers for producers that need SARIF's full surface (code-flow graphs, fix suggestions, embedded links, multi-tool aggregation). Bareport's output shape is fixed and known ahead of time — one finding type, one severity model, no code flows — so hand-writing the dozen-or-so structs actually needed, with `omitempty` doing the "don't emit fields we don't use" work for free, produces a smaller, more auditable surface than depending on a library built for the whole spec. |
| 18 | A structured-logging library (e.g. `sirupsen/logrus` — per pkg.go.dev, checked live while writing this file, imported by **239,958** other packages, one of the highest-importer-count packages in the entire Go ecosystem — or `uber-go/zap`) for `--verbose`'s structured scan-lifecycle logging | `log/slog` (stdlib since Go 1.21), `slog.NewJSONHandler` writing to stderr (`cli.go`'s `runScan`) | `log/slog` shipped in the standard library specifically to obsolete the years-long "which structured logging library" debate logrus/zap/zerolog represented — it's now the default answer, not a compromise. Bareport's `--verbose` mode needs exactly what `slog.Logger.Info(msg, "key", value, ...)` already provides: leveled, structured, JSON-capable logging to an arbitrary `io.Writer`, kept on a separate stream (stderr) from the human-facing report (stdout) so scripting/debugging use never collides with normal output. |
| 19 | A coverage-guided fuzzing framework (e.g. AFL, libFuzzer bindings via `dvyukov/go-fuzz` before Go had this natively) to fuzz `ClassifyBanner` — the banner parser that runs on genuinely untrusted input (whatever bytes a scanned, possibly-hostile service sends back first) | `testing.F` / `go test -fuzz` (stdlib coverage-guided fuzzing engine, built into `go test` since Go 1.18) (`tests/banner_fuzz_test.go`) | Most languages need a separate, often third-party fuzzing framework to get coverage-guided input generation at all; Go ships one directly in `go test`, so `FuzzClassifyBanner`'s seed corpus and crash-regression corpus are just more files in `tests/`, not a new tool in the dependency graph. |

## Package Killer bundle

Five of the substitutions above form a coherent "kill the CLI-polish
stack" bundle — the packages a typical polished Go CLI would reach for
one after another, all replaced with a few hundred lines of stdlib
total:

1. **`fatih/color`** (terminal color) → raw ANSI + `os.Stdout.Stat()` TTY check — entry #1, **27,995 importers**
2. **`olekukonko/tablewriter`** (table formatting) → `text/tabwriter` — entry #6
3. **`schollz/progressbar`** (progress bars) → `time.Ticker` + ANSI redraw — entry #14
4. **`spf13/cobra`** (CLI framework) → `flag` — entry #12, **195,884 importers** (per pkg.go.dev, checked live — one of the highest-importer-count packages in the entire Go ecosystem, and the strongest single case in this bundle for the "millions of weekly downloads" framing the Package Killer prize rewards)
5. **`manifoldco/promptui`** (interactive prompts) → `bufio.Scanner` on stdin — entry #15

Every one of these is a real, commonly-reached-for package in the Go
CLI ecosystem — colors, prompts, and "fancier components" (bubbletea)
are literally named together as the natural progression from a plain
`flag`-based CLI in community writeups of the Go CLI-building
ecosystem. None of them were needed here.

## Why These Dependencies Were Unnecessary

For every substitution in the table above, the same honest question:
what does the third-party package actually buy you, and what did
bareport give up by not using it? Grouped by what the package
normally does, since several table rows share the same answer.

**Terminal styling (fatih/color, olekukonko/tablewriter,
schollz/progressbar, charmbracelet/bubbletea)**
- *Why developers reach for these:* consistent cross-platform ANSI
  handling, prebuilt widgets (tables, bars, TUI layouts), less
  boilerplate.
- *Stdlib replacement:* raw ANSI escape sequences + `os.Stdout.Stat()`
  for TTY detection, `text/tabwriter` for column alignment,
  `time.Ticker` + cursor-control codes for live redraws.
- *Trade-off, honestly:* these libraries also handle Windows legacy
  console quirks (pre-Windows 10 cmd.exe didn't interpret ANSI codes
  natively) and terminal-width detection edge cases that bareport's
  hand-rolled version does not attempt. On a modern terminal (which is
  what CI runners and current OSes use) there's no practical
  difference; on an ancient Windows console, colors may not render.
- *What bareport implemented itself:* `report/color.go`,
  `report/table.go`, `report/live.go` — roughly 250 lines total across
  the three, none of it protocol-complex.

**CLI parsing & prompts (spf13/cobra, manifoldco/promptui)**
- *Why developers reach for these:* subcommands, auto-generated help
  text, shell completion, validated/styled interactive prompts.
- *Stdlib replacement:* `flag.FlagSet` plus a two-line special case on
  `os.Args[0]` for the `diff` and `why-zero-dep` subcommands;
  `bufio.Scanner` for the one interactive prompt bareport has.
- *Trade-off, honestly:* no shell completion, no auto-generated nested
  help per subcommand, no input validation loop (retry-on-bad-input) in
  the prompt — it's a single read, and a bad answer just falls through
  to the normal "no targets given" error.
- *What bareport implemented itself:* `main.go`'s `parseFlags` and
  `promptForTarget`.

**HTTP/TLS/DNS (an HTTP client library, a cert-parsing library,
miekg/dns)**
- *Why developers reach for these:* nicer request-builder APIs, DNS
  record types beyond what a stub resolver exposes, convenience
  wrappers around certificate fields.
- *Stdlib replacement:* `net/http`, `crypto/tls` + `crypto/x509`,
  `net.Resolver`.
- *Trade-off, honestly:* genuinely none found for bareport's use case
  — every field/behavior the scanner needs (redirect chains, cert
  SANs/expiry, MX/TXT lookups) is directly exposed by stdlib. This is
  the strongest "the dependency really was unnecessary" case in the
  whole list, not a compromise.
- *What bareport implemented itself:* `scanner/http.go`,
  `scanner/tls.go`, `scanner/dns.go`.

**Encoding (a JSON library, a CSV library)**
- *Why developers reach for these:* marginal throughput gains at very
  high message volume, occasionally friendlier struct-tag ergonomics.
- *Stdlib replacement:* `encoding/json`, `encoding/csv`.
- *Trade-off, honestly:* `encoding/json`'s reflection-based
  marshal/unmarshal is measurably slower than the fastest third-party
  alternatives at high throughput. A scan report serialized once per
  run is nowhere near that regime, so the trade-off costs nothing in
  practice here.
- *What bareport implemented itself:* `report/json.go`,
  `report/assessment.go`, `report/csv.go`.

**Concurrency (a worker-pool package, a cancellation library)**
- *Why developers reach for these:* pool resizing, backpressure
  metrics, structured-concurrency ergonomics beyond raw channels.
- *Stdlib replacement:* `sync.WaitGroup` + buffered channels for the
  worker pools; `context.Context` for cancellation, wired to OS signals
  via `signal.NotifyContext`.
- *Trade-off, honestly:* no live pool resizing (worker count is fixed
  for a given run via `--workers`) and no built-in metrics — bareport
  doesn't need either, since a scan's concurrency is decided once at
  startup, not adjusted mid-run.
- *What bareport implemented itself:* `scanner/tcp.go`,
  `scanner/udp.go`, `scanner/discovery.go`, `scanner/orchestrate.go`.

**Frontend (a JS framework + build step)**
- *Why developers reach for these:* component reuse, client-side
  state management, richer interactivity than server-rendered HTML.
- *Stdlib replacement:* `html/template` + `embed`, with a small amount
  of hand-written vanilla JS for sort/filter inlined directly in the
  page.
- *Trade-off, honestly:* no client-side routing, no reactive
  re-rendering — every interaction that needs new data (the diff view,
  for instance) is a full page navigation, not an in-place update. For
  a local security-report viewer opened once per scan, this is not a
  meaningful loss.
- *What bareport implemented itself:* `web/server.go`,
  `web/templates/dashboard.html`, `report/html.go` +
  `report/html_templates/report.html`.

**Testing (testify, ginkgo/gomega)**
- *Why developers reach for these:* fluent assertion syntax
  (`assert.Equal`), BDD-style test structure, richer failure-diff
  output.
- *Stdlib replacement:* `testing`, with plain
  `if got != want { t.Errorf(...) }` comparisons.
- *Trade-off, honestly:* more verbose at the call site, and failure
  output is a plain message rather than a structured diff. Given the
  test count in this project (see README's coverage section), that
  verbosity cost is small and the dependency isn't worth it.
- *What bareport implemented itself:* every file under `tests/`.

## Narrative detail (why each package is used *where*, for the rebuild)

### Core scanning engine

**`net`** — the workhorse. `net.Dialer`/`DialContext` for TCP connects
(`scanner/tcp.go`), `net.DialUDP` for UDP (`scanner/udp.go` — note
*why* Dial not Listen+WriteTo: a connected socket is what lets the OS
attribute an ICMP port-unreachable error back to us via `Read`),
`net.ParseCIDR` + manual byte-increment for CIDR expansion
(`scanner/targets.go` — there's no stdlib `CIDRHosts()` helper, you
have to roll it), `net.JoinHostPort`/`SplitHostPort` everywhere instead
of string concatenation (handles IPv6 bracket syntax for free).

**`context`** — cancellation plumbing. Every worker pool selects on
`ctx.Done()` both when pulling jobs off the channel and (implicitly)
via `DialContext`'s context-aware dial. `signal.NotifyContext` in
`main.go` is the single place SIGINT/SIGTERM turns into a cancelled
context; nothing downstream needs to know about signals at all.

**`sync`** — `sync.WaitGroup` to know when all workers have drained a
job channel (`scanner/tcp.go`, `udp.go`, `discovery.go`), plus one
`sync.Mutex` in `discovery.go` guarding a shared map written from
multiple goroutines. Deliberately no other shared mutable state —
almost everything else is channel-passed instead of mutex-guarded.

**`time`** — `time.Duration` for every timeout/interval config field,
`context.WithTimeout` pairs with it constantly. `time.Since`/`time.Now`
for latency measurement per-probe.

**`syscall`** (`scanner/fingerprint_linux.go`) — the one place this
project reaches below `net`'s abstraction. Reading a live socket's
`IP_TTL` option isn't exposed by `net.TCPConn`'s public API at all;
`syscall.GetsockoptInt` is the only stdlib path to it, which is why
that file exists split out behind a `//go:build linux` tag with a
graceful non-Linux fallback (`fingerprint_other.go`) rather than one
file — the option constants aren't portable across OS.

**`crypto/tls` + `crypto/x509`** — `tls.Client` + `HandshakeContext`
for the inspection handshake (`scanner/tls.go`), with
`InsecureSkipVerify: true` **on purpose**: we want to complete the
handshake against self-signed/expired certs so we can inspect and
report on exactly those problems, then do our own validity checks
manually (`tlsFindings`) instead of letting the stdlib's verifier
reject the connection before we ever see the cert. `x509.Certificate`
fields (`NotAfter`, `Subject`, `Issuer`, `DNSNames`) are the whole
payload of `TLSInfo`. In `demo-targets/`, `x509.CreateCertificate` +
`crypto/ecdsa` generate certs in-process — no openssl shell-out.

**`net/http`** — both as a client (`scanner/http.go`'s custom
`http.Client` with a `CheckRedirect` hook to record the redirect
chain) and as a server (every `demo-targets/*.go` file, and
`web/server.go`'s dashboard).

**`bufio`** — `bufio.Reader`/`ReadString` in `scanner/banner.go` for
line-oriented banner reads, and `bufio.Scanner` in `scanner/targets.go`
for reading host list files line-by-line.

### Reporting

**`text/tabwriter`** — see substitution #6 above.

**`encoding/json`** — see substitution #4 above. Always with
`SetIndent` for human-readable output files.

**`encoding/csv`** — see substitution #9 above.

**`sort`** — `sort.SliceStable` in `web/server.go` to order dashboard
rows worst-severity-first while keeping host order stable as a
secondary sort.

**`flag`** — see substitution #12 above.

**`report/live.go`'s `LiveDashboard`** — see substitutions #13/#14
above (`charmbracelet/bubbletea`, `schollz/progressbar`). Worth saying
plainly: this is a live-updating, in-place-redrawing terminal display —
the exact category of thing most Go developers reach for a TUI
framework to build — and it uses zero of one. Two stdlib pieces make it
work: `sync.Mutex`-guarded snapshot storage (`Update` is
called from the scan's hot path and must never block on terminal I/O),
and a `time.Ticker`-driven redraw goroutine that reads the latest
snapshot and repaints in place. `scanner.Run`'s progress reporting
(`ProgressSnapshot`, `ProgressFunc`) uses `sync/atomic`'s typed atomic
counters (`atomic.Int64`) rather than a mutex, since it's independent
counters being incremented from a single scanning goroutine while read
concurrently by the dashboard's ticker goroutine — atomics are the
right-sized tool there, a mutex would be overkill for four independent
counters.

**`report/diff.go` and `report/security_drift.go`** — see substitution
#16 above. Also worth saying plainly: this is a structural diff between
two full scan results — ports, services, findings, TLS certs, a risk
score — the kind of comparison most developers would reach for a
diffing library to get right, and it uses zero of one. Every comparison
here is a plain Go map built once per side and compared with ordinary
lookups; `sort.Slice`/`sort.SliceStable` (already used elsewhere in
this package) keep each diff category's output order deterministic.

### Web dashboard

**`html/template`** — see substitution #5 above. Note there's a
security reason too, not just a build-pipeline one: `html/template`
(not `text/template`) auto-escapes any scan-derived string (a hostile
banner, a weird cert Subject field) that ends up in the HTML output —
a real concern for a tool that renders attacker-influenced strings
into a browser.

**`embed`** — `//go:embed templates/*.html` and `//go:embed
static/*.css` bake the dashboard into the compiled binary.

### DNS

**`net`'s `Resolver`** — see substitution #10 above.

### Misc

**`os`/`os/signal`/`syscall`** — process-level concerns in `main.go`:
argv, exit codes, Ctrl+C.

**`log`** — used sparingly for operational messages (server started,
non-fatal lookup failures) — never for the scan *report* itself, which
always goes through the `report` package so its shape is controlled.

**`strings`/`strconv`** — parsing flag values (`--ports 22,80-90`),
trimming, prefix checks throughout.

**`net.Interfaces()`/`net.Interface.Addrs()`** (`scanner/targets.go`'s
`LocalSubnet`) — backs `--local-network`: enumerate the machine's own
network interfaces and pick the first non-loopback IPv4 address's
subnet, entirely through `net`, with no shell-out to `ip addr` or
`ifconfig` and no OS-specific parsing.

**`bufio.Scanner` on stdin** — see substitution #15 above
(`main.go`'s `promptForTarget`).

**`testing`** — see substitution #11 above. `tests/scanner_test.go`
spins up in-process HTTP/TLS/TCP servers (mirroring what
`demo-targets/*.go` do standalone) and asserts real scanner behavior
against them; `tests/scanner_bench_test.go` benchmarks `ScanTCP`
throughput across worker-pool sizes.

### Security assessment layer (new: findings/, risk/, whyzerodep/, integration/)

**`findings/`** — pure Go, no new stdlib packages beyond `sort` (for
deterministic worst-first ordering) and `net` (in `tls.go`, to
recognize an IP-literal target so the hostname-mismatch rule doesn't
fire without real evidence — see that file's doc comment). Every rule
here reads data `scanner/` already collected; nothing makes an
additional network call.

**`risk/`** — pure Go, no I/O, no new stdlib dependency at all. It's a
deterministic function of `[]findings.Finding` — see that package's
own doc comment for why it's explicitly not CVSS.

**`whyzerodep/`** — a static data package, no I/O.

**`integration/`** — one of two places `os/exec` appears in the whole
codebase (the other is `tools/gen_selfaudit.go`, covered under
`selfaudit/` below), and it deserves a direct callout: **the shipped
`bareport` binary itself never shells out to anything, at any point,
for any feature.** `os/exec` is used here exclusively by
`integration/main.go`, a separate developer/CI tool (`make
integration-test`) that builds and drives the real `bareport` binary
and the real `demo-targets/` servers as subprocesses to black-box test
them — the same category of thing `go test` itself does when it
compiles and runs a test binary. This is not a hidden runtime
dependency of the product; it's test tooling that happens to also be
written in Go, and it isn't part of what `go build .` at the repo root
produces. `runtime.Caller` is used the same way `demo-targets/run-all.go`
already used it, to resolve the repo root regardless of the caller's
working directory.

**`selfaudit/`** — behind `bareport --verify-zero-dep`: cross-checks
bareport's own import graph against the real Go standard library and
reports pass/fail, at runtime, from inside the shipped binary. The
data it checks (bareport's own `go list -deps .` output, and `go list
std`'s full package table) is captured once at build/generate time by
`tools/gen_selfaudit.go` — the second of the two places `os/exec`
appears in this codebase, and like `integration/`, it's a
`//go:build ignore`d file that is never part of `go build .`'s output.
The alternative — having `--verify-zero-dep` shell out to `go list`
itself, at runtime, inside the shipped binary — was deliberately
rejected: it would make the self-audit command the one feature that
needs the Go toolchain installed just to run, breaking the "single
compiled artifact, nothing else needed" story everything else in this
README leans on, and it would turn `os/exec` from "test tooling only"
into "a real runtime dependency of the product." Generating the
snapshot once and embedding it keeps the shipped binary's proof
self-contained: the binary can prove what its *own build* looked like,
without needing to re-derive it live every run.

## Explicitly excluded, and why

Per the rules, `golang.org/x/*` packages are **not** stdlib despite
being Go-affiliated, and are never imported anywhere in this project —
confirmed by `make deps-proof`, which lists exactly one module (this
one) in the entire build graph. The one place this shows up as a real
design constraint rather than just a checkbox: raw ICMP (a "real"
ping, or true UDP open/closed disambiguation) would normally reach for
`golang.org/x/net/icmp`. Excluded here, it's out of reach without
either root privileges (`net.ListenIP` with `"ip4:icmp"` needs
`CAP_NET_RAW`/root on Linux for a raw socket) or that excluded package.
`scanner/discovery.go` and `scanner/udp.go` each carry a comment
explaining exactly what signal is lost by staying stdlib-only, and
README.md documents the TCP-liveness-vs-ICMP tradeoff explicitly,
rather than silently pretending the substitute is equivalent.
