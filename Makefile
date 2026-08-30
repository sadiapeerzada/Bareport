# bareport — Zero Dependency hackathon build targets.
#
# make build              -> single runnable artifact: ./bareport
# make deps-proof         -> proves zero third-party modules (deps-proof.txt)
# make verify-reproducible -> builds twice, hashes both, asserts they match
# make selfaudit-manifest -> regenerates selfaudit/manifest_generated.go
# make test               -> go test ./...
# make demo               -> starts all demo-targets servers (foreground)
# make clean              -> removes build artifacts

BINARY := bareport

# LDFLAGS explained (each flag matters for genuinely reproducible,
# stripped output — this is not just "go build" with extra noise):
#
#   -buildid=    Go embeds a randomly-generated build ID into every
#                binary by default, specifically so tools like the
#                linker can detect stale cached objects. That ID is
#                NOT derived from source content — it changes between
#                otherwise-identical builds — so it is the single
#                biggest source of non-determinism in a default `go
#                build` output. Setting it to the empty string strips
#                it entirely, which is a prerequisite for
#                verify-reproducible below to ever pass.
#   -s           Omit the symbol table. Smaller binary; also removes
#                information that isn't needed at runtime and has no
#                bearing on reproducibility by itself, but is the
#                conventional pairing with -w for a "stripped" release
#                build.
#   -w           Omit the DWARF debug info. Same rationale as -s —
#                stripped release binaries don't ship a debugger's
#                worth of metadata.
LDFLAGS := -trimpath -ldflags="-buildid= -s -w"

.PHONY: build deps-proof verify-reproducible test test-race integration-test selfaudit-manifest demo demo-fix-rescan clean

build:
	go build $(LDFLAGS) -o $(BINARY) .
	@echo "built ./$(BINARY)"

# deps-proof: `go list -m all` lists every module in the build graph,
# starting with the main module itself. For a genuinely zero-dependency
# project this prints exactly ONE line (the module itself) and nothing
# else — no third-party modules exist to list, because go.mod has no
# require directives at all. Writing the raw output to a file makes the
# claim independently checkable by anyone reading the submission,
# rather than asking them to trust go.mod alone.
deps-proof:
	go list -m all > deps-proof.txt
	@echo "wrote deps-proof.txt:"
	@cat deps-proof.txt
	@lines=$$(wc -l < deps-proof.txt); \
	if [ "$$lines" -ne 1 ]; then \
		echo "FAIL: expected exactly 1 module (this one), got $$lines — third-party deps present"; \
		exit 1; \
	fi
	@echo "OK: exactly one module in the build graph (zero third-party dependencies)"

# verify-reproducible: builds the binary twice with identical flags
# (see LDFLAGS above — -trimpath strips local filesystem paths from
# the binary so the build machine's absolute paths don't leak into —
# and don't vary — the output; -buildid=/-s/-w strip the remaining
# sources of non-determinism and incidental metadata) and asserts the
# two builds are byte-identical via sha256. This is a meaningful claim
# for a Go binary specifically because Go's toolchain does NOT embed
# build timestamps by default (unlike some other compilers), so two
# builds from the same source and toolchain version should already
# match without any special SOURCE_DATE_EPOCH handling, given the
# build-id is also stripped.
verify-reproducible:
	go build $(LDFLAGS) -o /tmp/bareport-build-a .
	go build $(LDFLAGS) -o /tmp/bareport-build-b .
	@hash_a=$$(sha256sum /tmp/bareport-build-a | cut -d' ' -f1); \
	hash_b=$$(sha256sum /tmp/bareport-build-b | cut -d' ' -f1); \
	echo "build A sha256: $$hash_a"; \
	echo "build B sha256: $$hash_b"; \
	if [ "$$hash_a" != "$$hash_b" ]; then \
		echo "FAIL: builds are not reproducible"; \
		exit 1; \
	fi; \
	echo "OK: both builds are byte-identical"

test:
	go test -cover ./...

# test-race runs the unit suite under Go's race detector — real,
# stdlib-native concurrency verification (no third-party tooling) for
# a codebase whose core scan engine is worker-pool/goroutine-heavy
# (scanner/tcp.go, udp.go, discovery.go) and whose live dashboard
# (report/live.go) shares state between a scanning goroutine and a
# ticker-driven redraw goroutine — exactly the kind of code where a
# data race is easy to introduce silently.
test-race:
	go test -race ./tests/...

# integration-test runs the local integration-test lab (integration/main.go):
# builds the real bareport binary, starts the real demo-targets servers
# as subprocesses, runs the real binary against them, and asserts on
# its actual CLI output. Deterministic and localhost-only — see that
# file's doc comment for why this exists as a separate thing from
# `make test`.
integration-test:
	go run ./integration

# selfaudit-manifest regenerates selfaudit/manifest_generated.go: a
# build-time snapshot of `go list std` and bareport's own `go list
# -deps .` output, which `bareport --verify-zero-dep` cross-checks at
# runtime without shelling out itself. Run this after adding or
# removing any import anywhere in bareport, before relying on
# --verify-zero-dep's output — see tools/gen_selfaudit.go's doc
# comment for the full "why generate, not shell out at runtime"
# rationale. Not part of `make build`: regenerating needs the Go
# toolchain's `go list`, which is exactly the runtime dependency this
# design keeps out of the shipped binary.
selfaudit-manifest:
	go run tools/gen_selfaudit.go
	@echo "regenerated selfaudit/manifest_generated.go"

demo:
	go run demo-targets/run-all.go

# demo-fix-rescan: a runnable, terminal version of feature #3's
# Fix -> Rescan -> Verify cycle against demo-targets/vulnerable-app.go
# — the same sequence integration/main.go's "Fix -> Rescan -> Verify"
# check exercises programmatically, here as copy-pasteable shell so it
# can be run and watched directly. Builds the real binary and the real
# demo target (not `go run`), scans it in its default vulnerable
# state, flips it to fixed over its own HTTP endpoint, rescans, and
# runs the real `bareport diff` — nothing here is simulated.
demo-fix-rescan:
	@echo "building bareport and vulnerable-app..."
	@go build $(LDFLAGS) -o /tmp/bareport-demo-fixrescan .
	@go build -o /tmp/vulnerable-app-demo demo-targets/vulnerable-app.go
	@/tmp/vulnerable-app-demo -addr :18095 & \
	echo $$! > /tmp/vulnerable-app-demo.pid; \
	sleep 1; \
	echo; \
	echo "=== BEFORE: scanning vulnerable-app (default state) ==="; \
	/tmp/bareport-demo-fixrescan --targets 127.0.0.1 --ports 18095 --skip-discovery --no-live --format json --save /tmp/bareport-demo-before.json > /dev/null; \
	/tmp/bareport-demo-fixrescan --targets 127.0.0.1 --ports 18095 --skip-discovery --no-live --minimal; \
	echo; \
	echo "=== FIX: flipping vulnerable-app to its fixed state ==="; \
	curl -s -X POST http://127.0.0.1:18095/_bareport_demo/fix; \
	echo; \
	echo "=== RESCAN: scanning vulnerable-app again ==="; \
	/tmp/bareport-demo-fixrescan --targets 127.0.0.1 --ports 18095 --skip-discovery --no-live --format json --save /tmp/bareport-demo-after.json > /dev/null; \
	/tmp/bareport-demo-fixrescan --targets 127.0.0.1 --ports 18095 --skip-discovery --no-live --minimal; \
	echo; \
	echo "=== VERIFY: bareport diff before -> after ==="; \
	/tmp/bareport-demo-fixrescan diff /tmp/bareport-demo-before.json /tmp/bareport-demo-after.json; \
	kill `cat /tmp/vulnerable-app-demo.pid` 2>/dev/null; \
	rm -f /tmp/vulnerable-app-demo.pid /tmp/bareport-demo-before.json /tmp/bareport-demo-after.json /tmp/vulnerable-app-demo /tmp/bareport-demo-fixrescan

clean:
	rm -f $(BINARY) deps-proof.txt /tmp/bareport-build-a /tmp/bareport-build-b
