// Command bareport is a zero-dependency network reconnaissance and
// security auditing tool. See README.md for usage; see STDLIB.md for a
// package-by-package explanation of every standard-library choice made
// in this codebase.
//
// main() itself is deliberately trivial: every real behavior lives in
// the importable bareport/cli package (cli.Run), specifically so that
// logic is unit-testable. Package main is structurally excluded from
// Go's coverage tooling — `go test -coverpkg` can't attribute coverage
// to a package that test code isn't allowed to import — so keeping
// substantial logic here would make it look permanently untested in
// any coverage report, no matter how well the integration test lab
// (integration/main.go) actually exercises it black-box.
package main

import (
	"os"

	"bareport/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
