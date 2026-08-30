// Command run-all spins up every demo-targets server at once, each on
// its own well-known port, for one-command demo setup ahead of running
// bareport against them.
//
// WHY os/exec + A PRE-BUILT BINARY PER TARGET INSTEAD OF IMPORTING
// THEM DIRECTLY: Every other file in this directory (plain-http.go,
// selfsigned-https.go, expired-https.go, tcp-echo.go, udp-echo.go,
// vulnerable-app.go) is its own `package main` with its own func
// main(), tagged `//go:build ignore` so `go build ./...` at the module
// root doesn't choke on six conflicting mains sharing one directory.
// That means they aren't importable Go functions — the entire point
// of the flat, single-file-per-target layout is that any one of them
// can be run standalone with `go run demo-targets/plain-http.go`
// while you're iterating on it. run-all.go respects that same shape:
// it launches each as a child process via os/exec (part of the
// stdlib, not a third-party process manager) rather than duplicating
// their logic here. This file deliberately has NO `//go:build ignore`
// tag, since it's the one program in this directory meant to be built
// normally.
//
// WHY BUILD FIRST INSTEAD OF `go run <file>.go` DIRECTLY: `go run`
// forks the actual compiled binary as a CHILD of the `go run` process
// itself, and exec.CommandContext's cancellation only kills the
// process it directly started — `go run`, not its child. Two
// consequences, both real bugs this file used to have: (1) the
// prefixWriter below wraps os.Stdout in a plain io.Writer, so os/exec
// can't hand the child the file descriptor directly and instead pipes
// through a background copier — Wait() only returns once every
// process holding the write end of that pipe has closed it, and the
// grandchild inherits and keeps that write end open even after `go
// run` itself is killed, so shutdown hangs indefinitely; (2) even
// without the pipe, the grandchild server process would simply be
// orphaned and left listening. integration/main.go hit and documented
// the identical issue and fixed it the same way — see its
// startDemoTargets doc comment for the fuller explanation. Building
// each target to a temp binary once, then running that binary
// directly, means exec.CommandContext's kill-on-cancel targets the
// real server process, so both the pipe and the process actually
// close on Ctrl+C.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
)

// target pairs each demo source file with the address it should listen
// on, matching the defaults baked into each file's own -addr flag so
// this list is easy to keep in sync by eye.
type target struct {
	file string
	addr string
	name string
}

var targets = []target{
	{file: "plain-http.go", addr: ":8081", name: "plain-http"},
	{file: "selfsigned-https.go", addr: ":8443", name: "selfsigned-https"},
	{file: "expired-https.go", addr: ":8444", name: "expired-https"},
	{file: "tcp-echo.go", addr: ":2222", name: "tcp-echo"},
	{file: "udp-echo.go", addr: ":9999", name: "udp-echo"},
	{file: "vulnerable-app.go", addr: ":8090", name: "vulnerable-app"},
}

func main() {
	// Resolve sibling demo files relative to this source file's own
	// directory rather than assuming the caller's cwd is demo-targets/,
	// so `go run demo-targets/run-all.go` works from the repo root too.
	selfDir := filepath.Dir(mustSelfPath())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Build every target to a temp binary up front, before starting
	// any of them, so a build failure in one target is reported
	// immediately instead of surfacing later as a mysterious "why
	// didn't that server start" during the demo. See the package doc
	// comment above for why this replaced `go run <file>.go` directly.
	binaries := make(map[string]string, len(targets))
	for _, t := range targets {
		bin, err := buildTarget(selfDir, t)
		if err != nil {
			log.Fatalf("run-all: building %s: %v", t.name, err)
		}
		binaries[t.name] = bin
	}
	defer cleanupBinaries(binaries)

	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		go func(t target) {
			defer wg.Done()
			runTarget(ctx, binaries[t.name], t)
		}(t)
	}

	fmt.Println("bareport demo-targets: all servers starting — Ctrl+C to stop them together")
	fmt.Println("  plain-http        http://localhost:8081/")
	fmt.Println("  selfsigned-https  https://localhost:8443/  (self-signed cert)")
	fmt.Println("  expired-https     https://localhost:8444/  (expired cert)")
	fmt.Println("  tcp-echo          tcp://localhost:2222     (fake SSH banner)")
	fmt.Println("  udp-echo          udp://localhost:9999")
	fmt.Println("  vulnerable-app    http://localhost:8090/  (BEFORE/AFTER fix-rescan demo target)")

	<-ctx.Done()
	fmt.Println("\nrun-all: shutting down demo targets...")
	wg.Wait()
}

// buildTarget compiles a single demo-targets source file to a temp
// binary, mirroring integration/main.go's startDemoTargets — see the
// package doc comment above for why building first (rather than `go
// run`) is required for clean shutdown.
func buildTarget(dir string, t target) (string, error) {
	srcPath := filepath.Join(dir, t.file)
	binPath := filepath.Join(os.TempDir(), "bareport-demo-"+t.name)
	cmd := exec.Command("go", "build", "-o", binPath, srcPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go build: %w\n%s", err, out)
	}
	return binPath, nil
}

// cleanupBinaries removes the temp binaries built by buildTarget.
func cleanupBinaries(binaries map[string]string) {
	for _, bin := range binaries {
		os.Remove(bin)
	}
}

// runTarget runs one pre-built demo-target binary directly (not `go
// run`) so exec.CommandContext's kill-on-cancel targets the real
// server process itself — see the package doc comment above.
// Restart-on-exit is intentionally NOT implemented — a crashed demo
// target should be visible (in its logged output) rather than silently
// respawned, since this is a teaching/demo tool, not a production
// supervisor.
func runTarget(ctx context.Context, binPath string, t target) {
	cmd := exec.CommandContext(ctx, binPath, "-addr", t.addr)
	cmd.Stdout = prefixWriter{name: t.name, w: os.Stdout}
	cmd.Stderr = prefixWriter{name: t.name, w: os.Stderr}

	if err := cmd.Run(); err != nil && ctx.Err() == nil {
		// ctx.Err() == nil means the process exited on its own, not
		// because we cancelled it — that's worth surfacing.
		log.Printf("[%s] exited: %v", t.name, err)
	}
}

// prefixWriter tags each demo target's log lines with its name so
// run-all's combined output stays readable with five servers logging
// concurrently.
type prefixWriter struct {
	name string
	w    *os.File
}

func (p prefixWriter) Write(b []byte) (int, error) {
	_, err := fmt.Fprintf(p.w, "[%s] %s", p.name, b)
	return len(b), err
}

// mustSelfPath returns this source file's own path so sibling demo
// files can be located regardless of the caller's working directory.
// runtime.Caller is the stdlib mechanism for this; it's used here
// rather than assuming `go run` is always invoked from a fixed cwd.
func mustSelfPath() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		log.Fatal("run-all: could not resolve own source path via runtime.Caller")
	}
	path, err := filepath.Abs(file)
	if err != nil {
		log.Fatalf("run-all: resolving self path: %v", err)
	}
	return path
}
