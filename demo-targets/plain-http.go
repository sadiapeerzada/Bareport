//go:build ignore

// This file is built with `go run` individually or via run-all.go, not
// as part of the main module build (see the "ignore" build tag) —
// these are standalone demo programs, not library code bareport itself
// imports.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
)

// plainHTTPServer demonstrates section 7's header-audit feature: it
// deliberately sets SOME recommended security headers and omits
// others, so a scan against it produces a mix of pass/fail findings
// instead of an all-clear or all-fail (which would be less
// illustrative in a demo).
func main() {
	addr := flag.String("addr", ":8081", "listen address")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Present: X-Content-Type-Options, Referrer-Policy.
		// Missing (on purpose): Strict-Transport-Security,
		// X-Frame-Options, Content-Security-Policy.
		w.Header().Set("Server", "bareport-demo-plain-http/1.0")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		fmt.Fprintln(w, "bareport demo: plain HTTP target with partial security headers")
	})

	log.Printf("plain-http demo listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
