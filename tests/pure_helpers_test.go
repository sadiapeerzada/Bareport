package tests

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"bareport/cli"
	"bareport/config"
	"bareport/report"
	"bareport/scanner"
)

// ---- scanner/targets.go: ExpandTargets, expandCIDR, readHostFile, LocalSubnet ----

func TestTargets_ExpandTargets_SingleHost(t *testing.T) {
	got, err := scanner.ExpandTargets([]string{"example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != "example.com" {
		t.Errorf("expected [example.com], got %v", got)
	}
}

func TestTargets_ExpandTargets_CIDR(t *testing.T) {
	// A /30 has 4 addresses total; network+broadcast are excluded for
	// IPv4 blocks with more than 2 hosts, leaving exactly 2 usable.
	got, err := scanner.ExpandTargets([]string{"192.0.2.0/30"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"192.0.2.1", "192.0.2.2"}
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("expected %v, got %v", want, got)
			break
		}
	}
}

func TestTargets_ExpandTargets_SmallCIDR_NoExclusion(t *testing.T) {
	// A /31 (2 addresses) or smaller shouldn't have its only addresses
	// excluded as "network/broadcast" — that exclusion only applies
	// when there are more than 2 hosts to begin with.
	got, err := scanner.ExpandTargets([]string{"192.0.2.0/31"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 addresses for a /31, got %v", got)
	}
}

func TestTargets_ExpandTargets_InvalidCIDR(t *testing.T) {
	_, err := scanner.ExpandTargets([]string{"not-a-cidr/99"})
	if err == nil {
		t.Error("expected an error for a malformed CIDR")
	}
}

func TestTargets_ExpandTargets_HostFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.txt")
	content := "# a comment\nhost1.example.com\n\nhost2.example.com\n192.0.2.4/31\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing host file: %v", err)
	}

	got, err := scanner.ExpandTargets([]string{"@" + path})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"host1.example.com", "host2.example.com", "192.0.2.4", "192.0.2.5"}
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("expected %v, got %v", want, got)
			break
		}
	}
}

func TestTargets_ExpandTargets_MissingHostFile(t *testing.T) {
	_, err := scanner.ExpandTargets([]string{"@/tmp/bareport-test-file-does-not-exist.txt"})
	if err == nil {
		t.Error("expected an error for a missing host file")
	}
}

func TestTargets_LocalSubnet(t *testing.T) {
	// Every machine running this test has at least a loopback
	// interface and, in essentially any real environment (including
	// CI runners and this sandbox), at least one non-loopback IPv4
	// interface too — so this exercises the real code path rather
	// than mocking net.Interfaces(). If a given environment genuinely
	// has no such interface, LocalSubnet correctly returns an error,
	// which this test tolerates rather than treating as a failure.
	subnet, err := scanner.LocalSubnet()
	if err != nil {
		t.Skipf("no non-loopback IPv4 interface available in this environment: %v", err)
	}
	if !strings.Contains(subnet, "/") {
		t.Errorf("expected a CIDR-form result (host/prefix), got %q", subnet)
	}
}

// ---- scanner/ports.go: resolvePortPreset ----

func TestScanner_ResolvePortPreset(t *testing.T) {
	top100 := scanner.ResolvePortPreset("top100")
	if len(top100) == 0 {
		t.Error("expected a non-empty top100 preset")
	}
	top1000 := scanner.ResolvePortPreset("top1000")
	if len(top1000) != 1000 {
		t.Errorf("expected exactly 1000 ports for top1000, got %d", len(top1000))
	}
	if top1000[0] != 1 || top1000[999] != 1000 {
		t.Errorf("expected top1000 to be the contiguous range 1-1000, got [%d..%d]", top1000[0], top1000[999])
	}
	// Unknown preset name falls back to top100 rather than erroring —
	// confirm that documented fallback behavior.
	unknown := scanner.ResolvePortPreset("bogus")
	if len(unknown) != len(top100) {
		t.Error("expected an unknown preset name to fall back to top100")
	}
}

// ---- scanner/orchestrate.go: port classification helpers ----

func TestScanner_IsConventionallyEncryptedPort(t *testing.T) {
	if !scanner.IsConventionallyEncryptedPort(443) {
		t.Error("expected port 443 to be conventionally encrypted")
	}
	if scanner.IsConventionallyEncryptedPort(80) {
		t.Error("did not expect port 80 to be conventionally encrypted")
	}
}

func TestScanner_LooksLikeTLSPort(t *testing.T) {
	if !scanner.LooksLikeTLSPort(443, nil) {
		t.Error("expected port 443 to look like a TLS port even with no banner")
	}
	if !scanner.LooksLikeTLSPort(9999, nil) {
		t.Error("expected an unknown port with no banner to still be worth a TLS attempt (errs toward trying)")
	}
	if scanner.LooksLikeTLSPort(9999, &scanner.Banner{Protocol: "ssh"}) {
		t.Error("did not expect a port with a confirmed SSH banner to look like a TLS port")
	}
	if scanner.LooksLikeTLSPort(9999, &scanner.Banner{Protocol: "ftp"}) {
		t.Error("did not expect a port with a confirmed FTP banner to look like a TLS port")
	}
}

func TestScanner_LooksLikeHTTPPort(t *testing.T) {
	if !scanner.LooksLikeHTTPPort(80, nil) {
		t.Error("expected port 80 to look like an HTTP port")
	}
	if scanner.LooksLikeHTTPPort(9999, nil) {
		t.Error("did not expect an arbitrary unknown port with no banner to look like HTTP")
	}
	if !scanner.LooksLikeHTTPPort(9999, &scanner.Banner{Protocol: "http"}) {
		t.Error("expected a confirmed HTTP banner to look like an HTTP port regardless of port number")
	}
}

// ---- scanner/fingerprint.go: guessOSFromTTL ----

func TestScanner_GuessOSFromTTL(t *testing.T) {
	cases := []struct {
		ttl      int
		wantSubs string
	}{
		{0, "unknown"},
		{-5, "unknown"},
		{64, "Linux"},
		{50, "Linux"},
		{128, "Windows"},
		{100, "Windows"},
		{255, "Network gear"},
		{200, "Network gear"},
	}
	for _, c := range cases {
		got := scanner.GuessOSFromTTL(c.ttl)
		if !strings.Contains(got, c.wantSubs) {
			t.Errorf("GuessOSFromTTL(%d) = %q, want it to contain %q", c.ttl, got, c.wantSubs)
		}
	}
}

// ---- report/color.go: colorizeState, colorizeSeverity (indirectly, via WriteTable with color=true) ----

func TestReport_WriteTable_WithColor(t *testing.T) {
	r := sampleReport()
	var buf bytes.Buffer
	if err := report.WriteTable(&buf, r, true); err != nil {
		t.Fatalf("WriteTable with color: %v", err)
	}
	out := buf.String()
	// Raw ANSI escape codes should appear for the open port (state
	// color) and the warning-severity finding (severity color).
	if !strings.Contains(out, "\033[") {
		t.Error("expected raw ANSI escape codes in colored table output")
	}
}

// ---- report/table.go: rank, aliveLabel (indirectly, via a host with no ports) ----

func TestReport_WriteTable_HostWithNoPorts(t *testing.T) {
	r := &scanner.Report{
		Hosts: []scanner.HostResult{{Host: "192.0.2.99", Alive: false}},
	}
	r.Summarize()
	var buf bytes.Buffer
	if err := report.WriteTable(&buf, r, false); err != nil {
		t.Fatalf("WriteTable: %v", err)
	}
	if !strings.Contains(buf.String(), "down/unreachable") {
		t.Errorf("expected aliveLabel's down/unreachable text for a dead host with no ports, got: %s", buf.String())
	}
}

// ---- config/config.go: Load, Save ----

func TestConfig_SaveLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")

	cfg := config.Default()
	cfg.Targets = []string{"example.com", "10.0.0.0/24"}
	cfg.Workers = 250
	cfg.DoDNS = true

	if err := config.Save(path, cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := config.Load(path, config.Default())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Workers != 250 {
		t.Errorf("expected Workers=250 after round-trip, got %d", loaded.Workers)
	}
	if !loaded.DoDNS {
		t.Error("expected DoDNS=true after round-trip")
	}
	if len(loaded.Targets) != 2 {
		t.Errorf("expected 2 targets after round-trip, got %v", loaded.Targets)
	}
}

func TestConfig_Load_MissingFile(t *testing.T) {
	_, err := config.Load("/tmp/bareport-test-config-does-not-exist.json", config.Default())
	if err == nil {
		t.Error("expected an error loading a missing config file")
	}
}

func TestConfig_Load_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{not valid json"), 0o644); err != nil {
		t.Fatalf("writing malformed config: %v", err)
	}
	_, err := config.Load(path, config.Default())
	if err == nil {
		t.Error("expected an error loading a malformed config file")
	}
}

func TestConfig_Save_UnwritableDirectory(t *testing.T) {
	err := config.Save("/tmp/bareport-test-nonexistent-dir-xyz/save.json", config.Default())
	if err == nil {
		t.Error("expected an error saving to a directory that doesn't exist")
	}
}

// ---- report/diff.go: WriteDiff (the original, pre-SecurityAssessment port-level diff) ----

func TestReport_WriteDiff_PureOutput(t *testing.T) {
	before := sampleReport()
	after := sampleReport()
	after.Hosts[0].Ports = append(after.Hosts[0].Ports, scanner.PortResult{
		Host: "127.0.0.1", Port: 9000, Protocol: "tcp", State: scanner.StateOpen,
	})
	after.Summarize()

	d := report.Compare(before, after)
	var buf bytes.Buffer
	if err := report.WriteDiff(&buf, d); err != nil {
		t.Fatalf("WriteDiff: %v", err)
	}
	if !strings.Contains(buf.String(), "9000") {
		t.Errorf("expected WriteDiff output to mention the newly-opened port 9000, got: %s", buf.String())
	}
}

func TestReport_WriteDiff_NoChanges(t *testing.T) {
	r := sampleReport()
	d := report.Compare(r, r)
	var buf bytes.Buffer
	if err := report.WriteDiff(&buf, d); err != nil {
		t.Fatalf("WriteDiff: %v", err)
	}
	if !strings.Contains(buf.String(), "No changes detected") {
		t.Errorf("expected a 'no changes' message, got: %s", buf.String())
	}
}

func TestReport_WriteDiff_AllFourChangeKinds(t *testing.T) {
	before := &scanner.Report{Hosts: []scanner.HostResult{{
		Host: "127.0.0.1",
		Ports: []scanner.PortResult{
			{Host: "127.0.0.1", Port: 22, Protocol: "tcp", State: scanner.StateOpen}, // will close
			{
				Host: "127.0.0.1", Port: 443, Protocol: "tcp", State: scanner.StateOpen,
				TLS:  &scanner.TLSInfo{DaysUntilExpiry: 10}, // still valid before
				HTTP: &scanner.HTTPInfo{SecurityHeaders: map[string]string{"X-Frame-Options": "SAMEORIGIN"}},
			},
		},
	}}}
	after := &scanner.Report{Hosts: []scanner.HostResult{{
		Host: "127.0.0.1",
		Ports: []scanner.PortResult{
			{Host: "127.0.0.1", Port: 8080, Protocol: "tcp", State: scanner.StateOpen}, // newly open
			{
				Host: "127.0.0.1", Port: 443, Protocol: "tcp", State: scanner.StateOpen,
				TLS:  &scanner.TLSInfo{DaysUntilExpiry: -1}, // newly expired
				HTTP: &scanner.HTTPInfo{SecurityHeaders: map[string]string{"X-Frame-Options": ""}},
			},
		},
	}}}

	d := report.Compare(before, after)
	var buf bytes.Buffer
	if err := report.WriteDiff(&buf, d); err != nil {
		t.Fatalf("WriteDiff: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"Newly open ports:", "8080",
		"Newly closed ports:", "22",
		"Certificates newly expired:",
		"Changed security headers:", "X-Frame-Options",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected WriteDiff output to contain %q, got:\n%s", want, out)
		}
	}
}

// ---- scanner/discovery.go: DiscoverHosts (partial coverage) ----

// TestScanner_DiscoverHosts_Loopback gives DiscoverHosts a real,
// reachable loopback target so its core map-building/concurrency
// logic gets direct coverage, without depending on any specific LAN
// topology being present in the test environment. Full multi-host LAN
// discovery (the actual --local-network use case) stays
// integration-tested via `make integration-test` against the real
// demo-targets servers — this unit test's honest scope is "does
// DiscoverHosts correctly report a reachable host as alive and
// correctly return a map keyed by every input host", not "does it
// correctly discover an entire unknown LAN", which isn't something a
// hermetic unit test can meaningfully assert on anyway (there's no
// fixed, known set of hosts on an arbitrary test machine's LAN).
func TestScanner_DiscoverHosts_Loopback(t *testing.T) {
	hosts := []string{"127.0.0.1", "192.0.2.99"} // one reachable, one reserved-for-docs unreachable
	result := scanner.DiscoverHosts(context.Background(), hosts, 10, 300*time.Millisecond)

	if len(result) != len(hosts) {
		t.Fatalf("expected a result entry for every input host, got %d entries for %d hosts", len(result), len(hosts))
	}
	if _, ok := result["127.0.0.1"]; !ok {
		t.Error("expected 127.0.0.1 to have an entry in the result map")
	}
	if _, ok := result["192.0.2.99"]; !ok {
		t.Error("expected 192.0.2.99 to have an entry in the result map (even if false)")
	}
}

// ---- scanner/udp.go: ScanUDP against a real UDP echo listener ----

func TestScanner_ScanUDP_OpenPort(t *testing.T) {
	addr, err := netResolveUDP(t, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolving: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	defer conn.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			n, raddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			conn.WriteToUDP(buf[:n], raddr)
		}
	}()

	host, portStr, _ := net.SplitHostPort(conn.LocalAddr().String())
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	results := scanner.ScanUDP(context.Background(), []string{host}, []int{port}, 5, 500*time.Millisecond)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].State != scanner.StateOpen {
		t.Errorf("expected an echoing UDP port to report StateOpen, got %s", results[0].State)
	}
}

func netResolveUDP(t *testing.T, addr string) (*net.UDPAddr, error) {
	t.Helper()
	return net.ResolveUDPAddr("udp", addr)
}

func TestScanner_ScanUDP_UnusedPort(t *testing.T) {
	// A definitely-unused high port with nothing listening — per
	// scanner/udp.go's documented heuristic, this can only honestly
	// report StateClosed (if the OS sends back an ICMP unreachable) or
	// StateOpenFiltered (if it doesn't) — never StateOpen.
	results := scanner.ScanUDP(context.Background(), []string{"127.0.0.1"}, []int{59999}, 5, 300*time.Millisecond)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].State == scanner.StateOpen {
		t.Error("did not expect an unused UDP port to report StateOpen")
	}
}

func TestScanner_ScanUDP_WithProgressCallback(t *testing.T) {
	calls := 0
	results := scanner.ScanUDP(context.Background(), []string{"127.0.0.1"}, []int{59998, 59997}, 5, 300*time.Millisecond, func(scanner.PortResult) {
		calls++
	})
	if calls != len(results) {
		t.Errorf("expected the progress callback to fire once per result (%d), got %d calls", len(results), calls)
	}
}

func TestScanner_ScanUDP_UnresolvableHost_ReportsFiltered(t *testing.T) {
	// A syntactically-malformed "host" (too many colon-separated groups
	// to ever be a valid IPv6 literal) forces net.ResolveUDPAddr to fail
	// immediately and deterministically, with no real DNS round-trip —
	// exercising probeUDP's very first error branch (resolve failure ->
	// StateFiltered), which the open/unused-port tests above never
	// reach since both of those resolve just fine.
	results := scanner.ScanUDP(context.Background(), []string{"1:2:3:4:5:6:7:8:9"}, []int{80}, 1, 300*time.Millisecond)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].State != scanner.StateFiltered {
		t.Errorf("expected StateFiltered for an address that can't even be resolved, got %s", results[0].State)
	}
}

// ---- scanner/types.go: Report.ExitCode (the deprecated original scheme) ----

func TestScanner_Report_ExitCode_Deprecated(t *testing.T) {
	clean := &scanner.Report{}
	clean.Summarize()
	if got := clean.ExitCode(); got != 0 {
		t.Errorf("expected 0 for a clean report, got %d", got)
	}

	warn := &scanner.Report{Hosts: []scanner.HostResult{{Host: "h", Ports: []scanner.PortResult{{
		Findings: []scanner.Finding{{Severity: scanner.SevWarning}},
	}}}}}
	warn.Summarize()
	if got := warn.ExitCode(); got != 1 {
		t.Errorf("expected 1 for a report with only warnings, got %d", got)
	}

	crit := &scanner.Report{Hosts: []scanner.HostResult{{Host: "h", Ports: []scanner.PortResult{{
		Findings: []scanner.Finding{{Severity: scanner.SevCritical}, {Severity: scanner.SevWarning}},
	}}}}}
	crit.Summarize()
	if got := crit.ExitCode(); got != 2 {
		t.Errorf("expected 2 when a critical is present (critical takes precedence over warning), got %d", got)
	}
}

// ---- cli.go: writeHTMLReport / writeSavedAssessment via a real scan through Run() ----

func TestCLI_HTMLAndSaveFlags_WriteRealFiles(t *testing.T) {
	dir := t.TempDir()
	htmlPath := filepath.Join(dir, "out.html")
	savePath := filepath.Join(dir, "out.json")

	var outBuf, errBuf bytes.Buffer
	code := cli.Run([]string{
		"--targets", "127.0.0.1", "--ports", "1", "--skip-discovery", "--no-live", "--no-color",
		"--html", htmlPath, "--save", savePath,
	}, &outBuf, &errBuf)
	_ = code

	htmlBody, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("expected --html to write %s: %v", htmlPath, err)
	}
	if len(htmlBody) == 0 || strings.Contains(string(htmlBody), "{{") {
		t.Error("expected a non-empty, fully-rendered HTML file")
	}

	saveBody, err := os.ReadFile(savePath)
	if err != nil {
		t.Fatalf("expected --save to write %s: %v", savePath, err)
	}
	if !strings.Contains(string(saveBody), "\"risk\"") {
		t.Error("expected the saved JSON to contain a risk field")
	}

	if !strings.Contains(errBuf.String(), "wrote HTML security report to") {
		t.Error("expected a confirmation message on stderr for --html")
	}
	if !strings.Contains(errBuf.String(), "saved assessment to") {
		t.Error("expected a confirmation message on stderr for --save")
	}
}
