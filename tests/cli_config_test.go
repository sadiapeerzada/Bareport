package tests

import (
	"encoding/json"
	"os"
	"testing"

	"bareport/config"
	"bareport/findings"
	"bareport/risk"
)

func TestApplyProfile_Quick(t *testing.T) {
	cfg, err := config.ApplyProfile(config.Default(), "quick")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.PortPreset != "top100" {
		t.Errorf("expected top100 ports for quick profile, got %s", cfg.PortPreset)
	}
	if cfg.DoDNS {
		t.Error("expected DoDNS=false for quick profile")
	}
	if cfg.DoFinger {
		t.Error("expected DoFinger=false for quick profile")
	}
	if cfg.Profile != "quick" {
		t.Errorf("expected cfg.Profile to be set to 'quick', got %q", cfg.Profile)
	}
}

func TestApplyProfile_Security(t *testing.T) {
	cfg, err := config.ApplyProfile(config.Default(), "security")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.PortPreset != "top1000" {
		t.Errorf("expected top1000 ports for security profile, got %s", cfg.PortPreset)
	}
	if !cfg.DoDNS || !cfg.DoTLS || !cfg.DoHTTP || !cfg.DoBanners {
		t.Error("expected DNS/TLS/HTTP/banners all enabled for security profile")
	}
}

func TestApplyProfile_Full(t *testing.T) {
	cfg, err := config.ApplyProfile(config.Default(), "full")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.DoFinger {
		t.Error("expected DoFinger=true for full profile")
	}
	if !cfg.DoDNS {
		t.Error("expected DoDNS=true for full profile")
	}
}

func TestApplyProfile_Empty_NoOp(t *testing.T) {
	base := config.Default()
	cfg, err := config.ApplyProfile(base, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.PortPreset != base.PortPreset || cfg.DoDNS != base.DoDNS || cfg.Workers != base.Workers {
		t.Error("expected empty profile to leave config unchanged")
	}
}

// TestCLI_DefaultInvocation_MatchesConfigDefault is a regression test
// for a bug where a plain `bareport --targets ...` run (no --profile,
// no --dns/--no-fingerprint/etc.) silently ignored config.Default()
// for the five scan-toggle fields: parseFlags registered --dns,
// --no-banners, --no-fingerprint, --no-tls, and --no-http with
// hardcoded literal defaults instead of deriving them from
// config.Default() (as every other flag in that function already
// does, e.g. --preset from def.PortPreset), then applied those flag
// values to cfg unconditionally. That happened to be harmless while
// config.Default() itself hardcoded matching literals, but once
// Default() started deriving DoDNS/DoFinger (among others) from
// ApplyProfile("security"), a no-flag run silently diverged from it:
// DNS reconnaissance stayed off and OS fingerprinting stayed on,
// the opposite of the documented default "security" posture,
// even though config.Default() itself resolved correctly.
func TestCLI_DefaultInvocation_MatchesConfigDefault(t *testing.T) {
	dir := t.TempDir()
	cfgPath := dir + "/resolved.json"
	_, stderr, code := runCLI(t, "--targets", "127.0.0.1", "--save-config", cfgPath)
	if code != 0 {
		t.Fatalf("expected exit code 0 for --save-config, got %d (stderr=%q)", code, stderr)
	}

	body, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("reading saved config: %v", err)
	}
	var resolved config.Config
	if err := json.Unmarshal(body, &resolved); err != nil {
		t.Fatalf("parsing saved config JSON: %v", err)
	}

	want := config.Default()
	if resolved.DoDNS != want.DoDNS {
		t.Errorf("a plain no-flag run resolved DoDNS=%v, want %v (config.Default())", resolved.DoDNS, want.DoDNS)
	}
	if resolved.DoFinger != want.DoFinger {
		t.Errorf("a plain no-flag run resolved DoFinger=%v, want %v (config.Default())", resolved.DoFinger, want.DoFinger)
	}
	if resolved.DoBanners != want.DoBanners {
		t.Errorf("a plain no-flag run resolved DoBanners=%v, want %v (config.Default())", resolved.DoBanners, want.DoBanners)
	}
	if resolved.DoTLS != want.DoTLS {
		t.Errorf("a plain no-flag run resolved DoTLS=%v, want %v (config.Default())", resolved.DoTLS, want.DoTLS)
	}
	if resolved.DoHTTP != want.DoHTTP {
		t.Errorf("a plain no-flag run resolved DoHTTP=%v, want %v (config.Default())", resolved.DoHTTP, want.DoHTTP)
	}
	if resolved.PortPreset != want.PortPreset {
		t.Errorf("a plain no-flag run resolved PortPreset=%q, want %q (config.Default())", resolved.PortPreset, want.PortPreset)
	}
}

func TestApplyProfile_Unknown(t *testing.T) {
	_, err := config.ApplyProfile(config.Default(), "bogus")
	if err == nil {
		t.Error("expected an error for an unknown profile name")
	}
}

func TestRiskExitCode(t *testing.T) {
	cases := []struct {
		fs   []findings.Finding
		want int
	}{
		{nil, 0},
		{[]findings.Finding{mkFinding(findings.SevInfo)}, 2}, // any finding at all -> 2
		{[]findings.Finding{mkFinding(findings.SevLow)}, 2},
		{[]findings.Finding{mkFinding(findings.SevCritical)}, 3},
		{[]findings.Finding{mkFinding(findings.SevCritical), mkFinding(findings.SevLow)}, 3}, // critical wins
	}
	for i, c := range cases {
		r := risk.Score(c.fs)
		if got := r.ExitCode(); got != c.want {
			t.Errorf("case %d: expected exit code %d, got %d (score=%d)", i, c.want, got, r.Score)
		}
	}
}
