//go:build ignore

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
)

// vulnerableAppServer is a purpose-built BEFORE/AFTER demo target: a
// single deterministic local HTTP server that starts in a
// deliberately vulnerable state and can be flipped to a fixed state
// on command, so a scan → fix → rescan → verify cycle can be
// demonstrated against something real instead of a scripted fixture.
//
// It is intentionally isolated from bareport's own scanner/findings/
// risk packages (see ARCHITECTURE.md's demo-targets/ entry) — this
// file imports nothing from bareport at all, exactly like every other
// file in this directory. It is something bareport scans, never
// something that decides what a finding is; every issue it exposes is
// a real, observable HTTP characteristic (a missing header, a
// disclosed Server string, an unflagged cookie, an unauthenticated
// endpoint) that findings/http.go's rules evaluate independently,
// after the fact, from what the scan actually saw.
//
// Vulnerable (default) state exposes four realistic, safe-to-scan
// issue categories at once:
//   - Missing security headers        (HSTS/CSP/X-Content-Type-Options/
//     Referrer-Policy/X-Frame-Options all absent)
//   - Information disclosure          (a verbose, version-bearing
//     Server header)
//   - Insecure cookie configuration   (session cookie with neither
//     Secure nor HttpOnly nor SameSite set)
//   - Exposed admin endpoint          (/admin returns real-looking
//     content with no authentication challenge at all)
//
// Fixed state addresses all four the conventional way: full security
// header set, a generic Server string with no version, a cookie with
// Secure+HttpOnly+SameSite=Strict, and /admin returning 401 with a
// WWW-Authenticate challenge.
//
// State is toggled over plain HTTP endpoints under /_bareport_demo/,
// so the fix step in a demo is a real HTTP call a scan can be rerun
// against afterward — not a config edit or a restart, and nothing
// about the toggle mechanism is scanned or reported on itself.
func main() {
	addr := flag.String("addr", ":8090", "listen address")
	flag.Parse()

	app := &vulnerableApp{}

	mux := http.NewServeMux()
	mux.HandleFunc("/", app.handleRoot)
	mux.HandleFunc("/admin", app.handleAdmin)
	mux.HandleFunc("/_bareport_demo/status", app.handleStatus)
	mux.HandleFunc("/_bareport_demo/fix", app.handleFix)
	mux.HandleFunc("/_bareport_demo/reset", app.handleReset)

	log.Printf("vulnerable-app demo listening on %s (state: vulnerable)", *addr)
	log.Printf("  fix:   curl -X POST http://localhost%s/_bareport_demo/fix", *addr)
	log.Printf("  reset: curl -X POST http://localhost%s/_bareport_demo/reset", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

// vulnerableApp holds the single piece of mutable state this demo
// target has: whether it's currently serving the vulnerable or the
// fixed response shape. atomic.Bool because handlers run concurrently
// (net/http serves each request on its own goroutine) and the fix/
// reset endpoints race against in-flight scans by design — a demo
// should survive being flipped mid-scan without a data race, same
// discipline the real scanner package holds itself to.
type vulnerableApp struct {
	fixed atomic.Bool
}

func (a *vulnerableApp) handleRoot(w http.ResponseWriter, r *http.Request) {
	if a.fixed.Load() {
		// Fixed state: full security header set, no version-bearing
		// Server string, hardened cookie.
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Server", "bareport-demo") // no version disclosed
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    "demo-session-token",
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		fmt.Fprintln(w, "bareport demo: vulnerable-app (FIXED state)")
		return
	}

	// Vulnerable state: no security headers at all, a Server header
	// that discloses a specific product/version pair (a realistic
	// information-disclosure shape — this is what a genuinely
	// misconfigured Apache/PHP stack looks like on the wire), and a
	// session cookie with none of the three protective flags set.
	w.Header().Set("Server", "Apache/2.4.49 (Ubuntu) PHP/7.4.3")
	http.SetCookie(w, &http.Cookie{
		Name:  "session",
		Value: "demo-session-token",
		Path:  "/",
		// Secure, HttpOnly, SameSite deliberately left unset.
	})
	fmt.Fprintln(w, "bareport demo: vulnerable-app (VULNERABLE state)")
}

func (a *vulnerableApp) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if a.fixed.Load() {
		w.Header().Set("WWW-Authenticate", `Basic realm="admin"`)
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	// Vulnerable state: a real admin surface reachable with no
	// authentication challenge whatsoever — exactly the shape
	// findings/http.go's exposed-admin-endpoint rule (opt-in via
	// --admin-paths, see scanner/http.go) is evidence for.
	w.Header().Set("Server", "Apache/2.4.49 (Ubuntu) PHP/7.4.3")
	fmt.Fprintln(w, "Admin Dashboard — 42 registered users, 3 pending approvals")
}

// handleStatus reports the current toggle state as JSON — used by the
// fix/rescan demo script (see Makefile's demo-fix-rescan target) to
// confirm the flip actually took effect before triggering a rescan,
// rather than assuming timing.
func (a *vulnerableApp) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"fixed": a.fixed.Load()})
}

func (a *vulnerableApp) handleFix(w http.ResponseWriter, r *http.Request) {
	a.fixed.Store(true)
	fmt.Fprintln(w, "vulnerable-app: switched to FIXED state")
}

func (a *vulnerableApp) handleReset(w http.ResponseWriter, r *http.Request) {
	a.fixed.Store(false)
	fmt.Fprintln(w, "vulnerable-app: switched to VULNERABLE state")
}
