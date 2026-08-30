// Package selfaudit implements the runtime logic behind
// `bareport --verify-zero-dep`: cross-check bareport's own import
// graph against the real Go standard library and report whether
// anything outside it snuck in.
//
// The two tables this checks against (stdlibPackages, ownImports) live
// in manifest_generated.go, a generated file — see
// tools/gen_selfaudit.go's doc comment for the full "why a build-time
// snapshot, not a runtime `go list` call" rationale. This file is the
// only hand-written logic in the package: everything data-shaped is
// generated, everything behavior-shaped is here and reviewable like
// any other source file.
package selfaudit

import (
	_ "embed"
	"strings"
)

// stdlibPackagesRaw is the real `go list std` output as of the last
// `go run tools/gen_selfaudit.go` (or `make selfaudit-manifest`) — one
// import path per line, embedded via go:embed rather than baked into
// manifest_generated.go as a Go literal like ownImports is. This is
// the specific table README.md's --verify-zero-dep write-up describes
// as "embedded into the binary at build time via go:embed from `go
// list std` output" — kept as a flat text file, the real command's
// real output unmodified, rather than reformatted into Go syntax.
//
//go:embed stdlib_packages.txt
var stdlibPackagesRaw string

func stdlibPackageSet() map[string]bool {
	lines := strings.Split(strings.TrimSpace(stdlibPackagesRaw), "\n")
	set := make(map[string]bool, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			set[l] = true
		}
	}
	return set
}

// Result is what `--verify-zero-dep` reports.
type Result struct {
	ModulePath       string
	GoDirective      string
	RequireLineCount int
	ImportsWalked    int
	OutsideStdlib    []string // empty means verified
}

// Verified reports whether every import bareport's own build graph
// contains is either part of the Go standard library or one of
// bareport's own packages.
func (r Result) Verified() bool {
	return len(r.OutsideStdlib) == 0
}

// Verify cross-checks ownImports (bareport's own import graph, as of
// the last `go run tools/gen_selfaudit.go`) against stdlibPackages
// (the real `go list std` output as of that same generation) and
// reports anything that's neither.
//
// Three things are treated as "fine, not a violation":
//
//  1. Anything literally present in stdlibPackages.
//  2. bareport's own packages (ModulePath itself, or anything under
//     ModulePath + "/").
//  3. Anything under a "vendor/" path segment. Go's build system
//     resolves vendor/ paths relative to the module that declares
//     them — user code cannot reach into another module's vendor/
//     tree, only that module's own build can. Since `make deps-proof`
//     independently confirms bareport's own module graph contains
//     exactly one module (bareport itself, no vendor/ directory
//     anywhere in this repo), any vendor/-prefixed import path that
//     shows up in bareport's *own* -deps output can only have been
//     injected by the Go standard library's own internal vendoring
//     (net/http vendors a stripped copy of parts of golang.org/x/net,
//     golang.org/x/crypto, and golang.org/x/text for HTTP/2, IDNA, and
//     related support) — it is not, and cannot be, a third-party
//     dependency bareport itself pulled in. `go list -json` confirms
//     this directly: every such entry reports `"Standard": true` and
//     `"Module": null`, rooted at the Go toolchain's own install
//     directory, not bareport's module.
func Verify() Result {
	r := Result{
		ModulePath:       ModulePath,
		GoDirective:      GoDirective,
		RequireLineCount: RequireLineCount,
	}

	stdlib := stdlibPackageSet()

	ownPrefix := ModulePath + "/"
	for _, imp := range ownImports {
		r.ImportsWalked++
		switch {
		case stdlib[imp]:
			continue
		case imp == ModulePath || strings.HasPrefix(imp, ownPrefix):
			continue
		case strings.HasPrefix(imp, "vendor/"):
			continue
		default:
			r.OutsideStdlib = append(r.OutsideStdlib, imp)
		}
	}

	return r
}
