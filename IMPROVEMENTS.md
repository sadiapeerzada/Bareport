# IMPROVEMENTS.md — open improvement areas, prioritized

A running, honest list of what's known to be incomplete or worth
doing next — not a roadmap fantasy, a list grounded in what's actually
missing or weak right now. Update this in the same PR that closes an
item, the same discipline README.md's own "keep numbers real" rule
asks for everywhere else.

## Testing

Current coverage: see README's Testing section for the live number
(`go test ./tests/... -coverpkg=./... -cover`) — measured fresh each
round of work, not left stale here.

Known, disclosed gaps, none hidden or silently worked around:

- **Live DNS lookup path** (`scanner/dns.go`) — `net.Resolver` has no
  dependency-injectable transport in the standard library, so the
  SPF/DMARC/MX lookup path is exercised by `make integration-test`
  against real DNS, not mocked in a unit test. `FuzzClassifyBanner`-style
  fuzzing of the *parsing* logic (once a response is in hand) is
  covered; the network round-trip itself isn't unit-testable without
  either a fake resolver (more machinery than the gap justifies) or a
  third-party DNS-mocking library (out of scope by definition here).
- **Raw-socket TTL read** behind OS fingerprinting
  (`scanner/fingerprint_linux.go`) — requires a real raw socket, which
  needs privileges a CI runner or `go test` sandbox won't reliably
  have; exercised manually and via integration testing against the
  demo-targets, not per-function unit coverage.
- **The live terminal dashboard's redraw loop** (`report/live.go`) —
  a ticker-driven, terminal-width-dependent render loop; correctness
  here is "does it look right on a real terminal," which
  `make test-race` (concurrency) and manual/recorded demo runs cover
  better than a unit assertion on rendered bytes would.
- **The web server's real network binding** (`web/server.go`) — now
  unit-tested directly: `Serve` is exercised against a real local
  `net.Listen` for clean startup/shutdown-on-cancellation, and against
  an already-bound address for the listen-failure branch (see
  `tests/web_test.go`). What's still left to `make integration-test`
  and manual runs is the fuller "does a real OS socket bind and serve
  real HTTP end-to-end alongside the rest of a genuine `--serve`
  invocation" story, not `Serve`'s own function-level branches.
- **`--watch`'s drift-detected and scan-failed branches**
  (`cli.runWatch`) — the initial-scan path and real signal-based
  cancellation are unit tested (`tests/cli_test.go`), but exercising
  an actual drift between two re-scans needs a target whose state
  genuinely changes mid-run, which was verified live (see README's
  Continuous mode section for the real captured output) rather than
  built as an automated test — the same category of gap as the DNS
  and raw-socket items above, not a different standard applied.

None of these are unknown or being quietly worked around; each is a
case where the realistic alternative to "not unit tested" was either
"tested a different, real way" (integration/manual) or "add scope this
project doesn't need" (a mocking framework, most of which would also
threaten the zero-dependency constraint).

## Features considered, not built (yet), and why

Ranked roughly by how close each got to "worth doing," not by
alphabetical order. (`bareport --watch` — continuous re-scan with live
drift printing — was on this list and is now done; see README's
[Continuous mode](./README.md#continuous-mode---watch) section.)

- **Live-updating `--serve` dashboard** (SSE, toggle between a
  live-during-scan view and the current static report view) — `net/http`
  supports Server-Sent Events natively (`text/event-stream`,
  `http.Flusher`), so this doesn't need a dependency; it needs
  restructuring `cli.go` to start the web server *before* the scan
  begins and stream `scanner.ProgressSnapshot` events to connected
  clients, rather than serving a report that's already fully computed.
  A real, scoped change — not started yet.
- **`.bareport.toml` config file** — deferred in favor of the config
  support that already exists: `--config <file.json>` /
  `--save-config <file.json>` (see Scan Profiles in README) covers the
  same "define once, run with no flags" use case. TOML specifically
  would mean hand-writing a TOML parser (not in the standard library,
  and the spec — nested tables, arrays, dotted keys — is a lot of
  surface for a config format bareport's needs don't actually require)
  purely to match a file extension; JSON already does the job with
  zero new code.
- **`--targets -` (stdin)** — small, mechanical, not yet wired.
- **`--porcelain`** (single-line-per-finding, distinct from `--json`,
  for shell-pipeline use) — small, not yet wired.
- **HTML report visual redesign** — the current `report/html.go`
  output is functional (single self-contained file, real data, no
  external resources) but hasn't had a dedicated design pass. Lower
  priority than the functionality-affecting items above.

## Known limitations (see README for the user-facing version)

README's own Limitations section is the canonical, current list
(UDP `open|filtered` heuristic, TCP-based host discovery instead of
ICMP, TTL-based OS fingerprinting, the risk score's deliberate
non-alignment with CVSS, findings being signal-based rather than
CVE-backed). Not duplicated here to avoid the two drifting out of
sync — if you're looking for "what does bareport not do," that
section is the source of truth.
