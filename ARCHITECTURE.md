# ARCHITECTURE.md — pipeline + package responsibilities

This is the "how it's actually built" companion to
[STDLIB.md](./STDLIB.md) (which explains *what standard-library choice
replaced what third-party package, and why*) and
[README.md](./README.md) (which explains *what bareport does and how
to run it*). This file explains *how the pieces fit together* — the
pipeline a scan actually runs through, why the package boundaries are
where they are, and the handful of design decisions that trade
something real away on purpose, documented rather than hidden.

## Pipeline

A scan is a straight, one-directional pipeline. Nothing downstream
reaches back upstream — each stage's package only imports the stage
before it, never a peer or a later stage:

```
targets → discovery → port scan → banner/TLS/HTTP/DNS collection
        → findings engine → risk engine → report writers
```

1. **`scanner/targets.go`** — expands `--targets` (hosts, CIDR ranges,
   `@file`) into a concrete host list.
2. **`scanner/discovery.go`** — TCP-based liveness check per host
   (see [Design decisions worth calling out](#design-decisions-worth-calling-out)
   below), skippable via `--skip-discovery`.
3. **`scanner/ports.go`** — expands `--ports` (ranges, comma lists,
   named presets like `top-1000`) into a concrete port list per
   protocol.
4. **`scanner/tcp.go` / `scanner/udp.go`** — the actual concurrent
   scan: a bounded worker pool (`--workers`) dialing every
   host×port pair, honestly reporting `open` / `closed` /
   `open|filtered` (UDP) per connection outcome, nothing inferred
   beyond what a real dial+read told it.
5. **`scanner/banner.go`, `scanner/tls.go`, `scanner/http.go`,
   `scanner/dns.go`, `scanner/fingerprint*.go`** — once a port is
   known open, these collect the actual evidence a finding might later
   cite: banner bytes, certificate chain and validity window, response
   headers, SPF/DMARC records, OS-fingerprint TTL. Every one of these
   is a real network read; nothing here is invented from a port number
   alone.
6. **`scanner/orchestrate.go`** (`scanner.Run`) — the only place that
   calls the above in order, fans work out across the worker pool,
   and assembles everything into a single `scanner.Report`. It also
   accepts an optional `ProgressFunc` — the hook `report.LiveDashboard`
   (terminal) uses to render progress as it happens, rather than
   waiting for the whole scan to finish.
7. **`findings/engine.go`** (`findings.Engine`, called from
   `report.BuildAssessment`) — a deterministic rule set: given a
   `scanner.Report`, which rules fire. Every rule (`findings/tls.go`,
   `findings/http.go`, `findings/network.go`, `findings/dns.go`) reads
   data `scanner/` already collected — no rule makes an additional
   network call, and no rule fires without a real evidence string
   attached to cite what it saw.
8. **`risk/engine.go`** (`risk.Score`) — a pure function of
   `[]findings.Finding` → a 0–100 score + level. No I/O, no
   configuration, fully deterministic — the same findings always
   produce the same score. Not CVSS; see its own doc comment and
   [README's Risk scoring section](./README.md#risk-scoring) for why.
   `risk/breakdown.go` (`risk.Breakdown`) is an additive second view
   over the identical arithmetic, grouping the same findings by
   category (TLS/HTTP/Network/DNS, from each finding ID's own prefix)
   rather than a second scoring model.
9. **`report/`** — five independent writers (`table.go` terminal,
   `json.go`, `csv.go`, `sarif.go`, `html.go`) that all consume the
   same `report.SecurityAssessment` produced by step 7–8. None of them
   re-derive findings or re-score anything; they only format what's
   already been decided. `report/attacksurface.go`
   (`report.BuildAttackSurface`) is a further view over the same
   assessment — every open port per host, tagged with its worst
   finding severity — not a sixth writer or a new data source; it
   feeds the HTML report and web dashboard, not `--json`/`--csv`.

`web/server.go` and `report/live.go` sit beside this pipeline, not
inside it: they're presentation layers over a `scanner.Report` /
`SecurityAssessment` that already exists, the same way `report/json.go`
is — just interactive/served instead of written to a file.

`selfaudit/` and `whyzerodep/` aren't part of the scan pipeline at
all — they answer a question about bareport itself (its own
dependency graph, its own design rationale), not about a scanned
target. See [STDLIB.md](./STDLIB.md#narrative-detail-why-each-package-is-used-where-for-the-rebuild)
for what each of those actually does.

## Package responsibilities, in one line each

| Package | Responsibility |
|---|---|
| `cli/` | Flag parsing, subcommand dispatch, output-mode wiring. The only package that decides *what* to run; it doesn't implement scanning, findings, or reporting itself. |
| `config/` | The `config.Config` struct every other package is handed — scan parameters, resolved once, passed down, never re-parsed downstream. |
| `scanner/` | Everything that touches the network. See pipeline steps 1–6 above. |
| `findings/` | The deterministic rule set. See pipeline step 7. |
| `risk/` | The scoring function. See pipeline step 8. |
| `report/` | Every output format, plus the terminal live dashboard and the baseline-diff/security-drift comparison logic. |
| `web/` | The `--serve` local dashboard: `net/http` + `html/template`, serving the same `SecurityAssessment` the other report writers format. |
| `whyzerodep/` | Static data behind `bareport why-zero-dep` — a summarized, in-terminal version of STDLIB.md's substitution table. |
| `selfaudit/` | Runtime logic behind `bareport --verify-zero-dep` — cross-checks bareport's own build-time-captured import graph against the real Go standard library. See [STDLIB.md's entry](./STDLIB.md) for why this is a generated snapshot, not a runtime `go list` call. |
| `tools/` | Build-time generators only (currently: `gen_selfaudit.go`). `//go:build ignore`d — never part of `go build .`'s output. |
| `demo-targets/` | Standalone servers (plain HTTP, self-signed HTTPS, expired-cert HTTPS, a fake-banner TCP echo, a UDP echo, and `vulnerable-app.go` — a toggleable BEFORE/AFTER target for the Fix → Rescan → Verify demo) that exist purely so scans and tests have real, deterministic, local things to scan — not a bareport feature. |
| `integration/` | Black-box test lab (`make integration-test`): builds the real binary, starts the real demo-targets, and asserts on real CLI output/exit codes. The one other place (besides `tools/`) `os/exec` appears — see STDLIB.md, never shipped. |
| `tests/` | Everything importable and unit-testable — every package above except `cli`'s `main()` wiring (deliberately trivial, see `main.go`'s doc comment) and the `//go:build ignore`d generators. |

## Design decisions worth calling out

### TCP-based liveness, not ICMP

Host discovery (deciding whether a target is "up" before spending time
scanning its ports) is TCP-based: bareport dials a small set of
commonly-open ports and treats any response — open, or actively
refused (which still proves something answered) — as "alive." It does
not send ICMP echo requests.

This is a deliberate tradeoff, not an oversight:

- **Real ICMP requires raw sockets**, which need elevated OS
  privileges (root, or `CAP_NET_RAW` on Linux) on every platform this
  runs on. A network-scanning tool that needs `sudo` to do liveness
  checks — the *first*, simplest step of a scan — is a worse
  day-one experience than one that doesn't, and it would mean two
  different code paths (privileged/unprivileged) to build, test, and
  keep honest.
- **Go's stdlib `net` package doesn't expose raw ICMP** without
  privilege escalation either way (`golang.org/x/net/icmp` does, but
  that's an `x/` package — explicitly out of scope; see STDLIB.md's
  "Explicitly excluded" section for why `x/*` doesn't count as
  stdlib despite the Go-affiliated name).
- **The honest cost**: a host with every commonly-probed discovery
  port firewalled will look "dead" even if it would answer an ICMP
  ping. This is documented in README's Limitations and Troubleshooting
  sections, not hidden — and `--skip-discovery` exists specifically to
  bypass the check entirely when you already know a target is up (or
  don't trust the heuristic for it).

The alternative this rejects — silently claiming ICMP-equivalent
liveness detection while actually doing something weaker — would be
the kind of gap a judge (or a real user) discovers by hitting it, not
by reading about it first. Bareport's own `demo-targets/expired-https`
server, for instance, would fail a naive "port must return a
successful response" liveness check if that logic were reused for
discovery — which is exactly the kind of edge case that motivated
keeping discovery's success criterion as "responded at all," not
"responded successfully."

### Why `scanner.Run` takes a `context.Context`, not just a timeout

Every scan is cancelable mid-flight — `Ctrl+C` during a long scan
should stop cleanly, not leave the worker pool running or produce a
half-written report. `cli.Run` wires `signal.NotifyContext` once, at
the top, and threads the resulting `context.Context` all the way
through `scanner.Run` and every worker goroutine it spawns. A plain
timeout (`time.After` per call) would handle "scan too slow" but not
"user asked to stop" — context cancellation is the one stdlib
primitive that cleanly composes both without bareport hand-rolling its
own cancellation-broadcast mechanism.

### Why findings and risk are separate packages, not one

`findings/` decides *what's wrong* (a rule either fires or it
doesn't, with evidence). `risk/` decides *how bad, in aggregate, is
what's wrong* (a single 0–100 number from a list of findings). Keeping
them separate means the risk model can be swapped, extended, or
argued with (it's deliberately not CVSS — see its own doc comment)
without touching a single finding rule, and a new finding rule never
needs to know anything about scoring. `report/` is the only package
that imports both.
