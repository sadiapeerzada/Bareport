# SECURITY.md — authorized use, data handling, disclosure

Bareport actively probes network hosts and services: it opens TCP/UDP
connections, reads banners, inspects TLS certificates, requests HTTP
resources, and queries DNS records. This document covers who should
run it against what, what it does with what it collects, and how to
report a problem in bareport itself.

## Authorized use only

**Only run bareport against hosts and networks you own, or have
explicit, documented authorization to test.** This means:

- Your own machines, your own lab, your own infrastructure.
- A target you have a signed engagement, pentest authorization, or
  bug-bounty program scope explicitly covering — and only within that
  scope (this includes port/target ranges, not just the domain name).
- Never a third party's production systems, a coworker's machine, a
  public service, or "just to see what happens."

Unauthorized scanning can violate computer-crime law (in the US,
statutes like the Computer Fraud and Abuse Act; equivalents exist in
most other jurisdictions), a target's terms of service or
acceptable-use policy, and your own network provider's policies —
independent of whether bareport's scan is "just reconnaissance" and
finds nothing sensitive. That responsibility sits with whoever runs
the scan, not with the tool. This is the same standard any port
scanner, vulnerability scanner, or network-mapping tool operates
under; bareport doesn't do anything unusually invasive relative to
that category, but it does actively touch the network, which passive
tools don't.

If you're using bareport as part of a security engagement, keep the
scope documentation (the authorization itself, not just the target
list) available for the duration of testing — not because bareport
requires it technically, but because "I had permission" is a claim
you should be able to back up if a target's monitoring flags the
scan.

## What bareport actually collects and does with it

Everything bareport reads comes from the scan target answering a real
network request bareport made — nothing is inferred, guessed, or
fabricated (see [ARCHITECTURE.md](./ARCHITECTURE.md)'s pipeline
section for exactly which package collects what). Concretely, a scan
may read: open/closed port state, service banners, TLS certificate
chains and metadata (not the private key — bareport never has or
needs it), HTTP response headers and status codes, and DNS TXT/MX/SPF/
DMARC records.

**Where that data goes:**

- **Nowhere, by default.** A normal scan reads targets, prints a
  report to your terminal, and exits. Bareport makes no calls to any
  service other than the scan targets themselves and — for DNS
  lookups — your system's configured resolver. There is no telemetry,
  no analytics, no phone-home of any kind; `make deps-proof`'s "exactly
  one module in the build graph" result is also, incidentally, proof
  there's no bundled analytics SDK to have hidden that in.
- **Locally, only if you ask.** `--save`, `--html`, `--json`,
  `--csv`, and `--format sarif` all write the scan results to a local
  file *you* name, on the machine *you're* running bareport on.
  Nothing is uploaded anywhere. `--config`/`--save-config` similarly
  only reads and writes local files.
- **Served locally, only if you ask.** `--serve` starts a local
  `net/http` server (default `127.0.0.1`, i.e. not reachable from
  other machines unless you explicitly bind it to `0.0.0.0` or a
  routable address) that shows the same report in a browser instead of
  a file. It's the same data, presented differently — not a new
  collection or transmission path.

**Sensitive findings in scan output**: a scan report can legitimately
contain sensitive-looking information about the *target* — expired
certificates, missing security headers, an exposed banner revealing a
software version. That's the point of the tool (surfacing exactly
this, so it can be fixed), but it also means treating scan output
files with the same care you'd treat any other security-assessment
artifact: don't commit `--save`/`--html` output for a real target to a
public repo, don't share it outside the authorized audience for that
engagement.

## Reporting a problem in bareport itself

If you find a bug in bareport that could cause it to behave unsafely
— for example, a crash on malformed input from a scanned target (the
kind of thing `FuzzClassifyBanner` in `tests/banner_fuzz_test.go`
exists to catch pre-emptively), a finding rule that fires incorrectly
in a way that could mislead a real assessment, or any case where
bareport does something to a target beyond what its documented flags
say it will do — open an issue describing the input and observed
behavior. Since this is a hackathon-scope project without a dedicated
security contact or CVE process, there's no formal embargo/disclosure
timeline to promise beyond "opened issues get looked at" — for
anything you'd consider genuinely sensitive before a fix ships, use
your judgment about how much reproduction detail to include publicly
versus what you'd want addressed first.

This document is about bareport as a tool, not about vulnerabilities
in whatever you scan with it — findings bareport reports about a
*target* aren't bareport bugs, and aren't reported here; they're
exactly what the tool is meant to surface, following the [authorized
use](#authorized-use-only) guidance above for what to do with them.
