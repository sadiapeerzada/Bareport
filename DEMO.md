# DEMO.md — demo video script (target: under 5 minutes)

Prioritizes showing things run for real over narrating. Each shot
notes which rubric criterion it's demonstrating in brackets.

Suggested terminal setup before recording: two panes/tabs side by
side (left: commands; right: `demo-targets/run-all.go` output, or
just keep it minimized), font large enough to read on a recording,
`--no-color` off (colors should show).

---

## Shot 1 — The pitch (0:00–0:15)

Say, on camera or as a title card, not typed:

> "bareport is a zero-dependency network security assessment tool.
> Every line is Go standard library — no third-party runtime
> dependencies at all."

Show `cat go.mod` on screen for 2 seconds — empty `require` block is
the whole pitch in one glance.

**[Craft]** — establishes the core claim before anything else.

## Shot 2 — Zero-dependency proof, live (0:15–0:40)

```
make deps-proof
```

Let the full output print — `go list -m all` showing exactly one
line (`bareport`), then the `OK: exactly one module` line. Don't
cut this short; the one-line output *is* the proof.

**[Craft]** — the single most important claim, shown running, not
described.

## Shot 3 — Reproducible build, live (0:40–1:05)

```
make verify-reproducible
```

Let both `sha256` lines print and the `OK: both builds are
byte-identical` line show clearly.

**[Craft]** — a second, independent proof point; judges can see two
matching hashes with their own eyes.

## Shot 4 — One-command build and a real scan (1:05–1:45)

```
make build
./bareport --targets 127.0.0.1 --ports 8081,8443,8444 --skip-discovery
```

(Requires `demo-targets/run-all.go` already running in the
background before recording — start it silently beforehand, don't
show the setup.)

Let the live ANSI progress dashboard actually redraw a few times
on screen before it finishes — this is the shot that sells
Innovation, so don't cut away from it early. Then let the full
output run through: the port table, the boxed BAREPORT SECURITY
ASSESSMENT summary, ending on the risk score and exit code.

```
echo $?
```

**[Functionality]** primarily (a real scan against real targets,
real findings, real risk score); **[Innovation]** for the live
redrawing dashboard — call it out verbally: *"that live-updating
readout is raw ANSI cursor codes and a time.Ticker — no TUI
library."*

## Shot 5 — The HTML report (1:45–2:20)

```
./bareport --targets 127.0.0.1 --ports 8081,8443,8444 --skip-discovery --html report.html
open report.html    # or: xdg-open report.html
```

Scroll through the rendered report for a few seconds: executive
summary/risk score at the top, then the findings table, expand one
finding via its `<details>` toggle to show the evidence/remediation
text.

**[Functionality]** and **[Craft]** — a genuinely useful, polished
deliverable, self-contained (mention: "one HTML file, works
offline, no CDN").

## Shot 6 — Baseline / drift detection (2:20–3:00)

```
./bareport --targets 127.0.0.1 --ports 8081 --skip-discovery --save baseline.json
./bareport --targets 127.0.0.1 --ports 8081,8444 --skip-discovery --save current.json
./bareport diff baseline.json current.json
```

Let the "SECURITY DRIFT DETECTED" output print in full — the new
port, new finding, and risk score delta lines are the payoff.

**[Innovation]** — call it out verbally: *"that's a full structural
diff across ports, services, findings, and risk score — plain Go
map comparisons, no diffing library."*

## Shot 7 — Zero-config LAN scan (3:00–3:25)

```
./bareport --local-network --ports 22,80,443 --skip-discovery
```

Let it print the auto-detected subnet line before the scan starts.

**[Innovation]** — call it out verbally: *"no IP typed in — it read
the machine's own network interfaces to pick the subnet."*

## Shot 8 — The web dashboard (3:25–3:55)

```
./bareport --targets 127.0.0.1 --ports 8081,8443,8444 --skip-discovery --serve
```

Open the printed URL in a browser. Show the risk overview box, then
scroll to the findings table and click one severity filter chip
(e.g. "critical") to show the client-side filtering actually work.

**[Functionality]** and **[Craft]** — a second, richer view of the
same data, live-served, zero JS framework.

## Shot 9 — Integration test lab (3:55–4:20)

```
make integration-test
```

Let the full "BAREPORT INTEGRATION TEST" output print, ending on
`12/12 PASS`.

**[Craft]** and **[Functionality]** — proves the whole pipeline
(scan → findings → risk → JSON → HTML → diff) works end-to-end
against real running servers, not just unit tests in isolation.

## Shot 10 — Close (4:20–4:45)

```
bareport why-zero-dep
```

Let a few lines scroll, then cut. Say, on camera or as a title
card:

> "STDLIB.md documents nineteen of these substitutions in full —
> including a 195,884-importer CLI framework and a 239,958-importer
> logging library, both replaced with stdlib alone."

**[Craft]** — closing on the depth of the substitution work, with
real numbers, is a stronger close than a generic "thanks for
watching."

---

## If time runs short, cut in this order (least to most important)

1. Shot 7 (LAN scan) — good but the smallest standalone payoff.
2. Shot 9 (integration test) — valuable but less visually interesting
   than the other shots.
3. Shot 6 (drift detection) — cut only as a last resort; it's one of
   the three named Innovation features.

Never cut Shots 2–5 — deps-proof, verify-reproducible, the live scan,
and the HTML report are the core of the submission.
