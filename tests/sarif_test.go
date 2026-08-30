package tests

import (
	"bytes"
	"encoding/json"
	"testing"

	"bareport/report"
)

func TestReport_WriteSARIF_WellFormed(t *testing.T) {
	a := report.BuildAssessment(sampleReport(), []string{"127.0.0.1"}, "full")

	var buf bytes.Buffer
	if err := report.WriteSARIF(&buf, a); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}

	// Required SARIF 2.1.0 top-level keys.
	if _, ok := doc["$schema"]; !ok {
		t.Error("expected a $schema key")
	}
	version, ok := doc["version"].(string)
	if !ok || version != "2.1.0" {
		t.Errorf("expected version 2.1.0, got %v", doc["version"])
	}
	runsRaw, ok := doc["runs"].([]interface{})
	if !ok || len(runsRaw) == 0 {
		t.Fatalf("expected a non-empty runs array, got %v", doc["runs"])
	}

	run, ok := runsRaw[0].(map[string]interface{})
	if !ok {
		t.Fatalf("runs[0] is not an object: %v", runsRaw[0])
	}
	tool, ok := run["tool"].(map[string]interface{})
	if !ok {
		t.Fatal("expected runs[0].tool")
	}
	driver, ok := tool["driver"].(map[string]interface{})
	if !ok {
		t.Fatal("expected runs[0].tool.driver")
	}
	if name, _ := driver["name"].(string); name != "bareport" {
		t.Errorf("expected driver name 'bareport', got %v", driver["name"])
	}
	rules, ok := driver["rules"].([]interface{})
	if !ok || len(rules) == 0 {
		t.Fatal("expected a non-empty rules array (the sample report has findings)")
	}

	results, ok := run["results"].([]interface{})
	if !ok || len(results) == 0 {
		t.Fatal("expected a non-empty results array")
	}

	validLevels := map[string]bool{"error": true, "warning": true, "note": true, "none": true}
	foundError := false
	for _, r := range results {
		res, ok := r.(map[string]interface{})
		if !ok {
			t.Fatalf("result is not an object: %v", r)
		}
		if _, ok := res["ruleId"]; !ok {
			t.Error("expected every result to have a ruleId")
		}
		level, _ := res["level"].(string)
		if !validLevels[level] {
			t.Errorf("unexpected SARIF level %q", level)
		}
		if level == "error" {
			foundError = true
		}
		msg, ok := res["message"].(map[string]interface{})
		if !ok || msg["text"] == "" {
			t.Error("expected every result to have a non-empty message.text")
		}
	}
	// sampleReport's expired self-signed cert is CRITICAL severity,
	// which must map to SARIF's "error" level per WriteSARIF's
	// documented mapping.
	if !foundError {
		t.Error("expected at least one 'error'-level result given the sample report's critical finding")
	}
}

func TestReport_WriteSARIF_DeduplicatesRules(t *testing.T) {
	// The sample report produces multiple HTTP-MISSING-* findings on
	// different ports in principle, but even within one port's set of
	// missing-header findings, each distinct rule ID should appear
	// exactly once in the rules array regardless of how many results
	// reference it.
	a := report.BuildAssessment(sampleReport(), []string{"127.0.0.1"}, "")

	var buf bytes.Buffer
	if err := report.WriteSARIF(&buf, a); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	var doc map[string]interface{}
	json.Unmarshal(buf.Bytes(), &doc)
	run := doc["runs"].([]interface{})[0].(map[string]interface{})
	rules := run["tool"].(map[string]interface{})["driver"].(map[string]interface{})["rules"].([]interface{})

	seen := map[string]bool{}
	for _, r := range rules {
		id := r.(map[string]interface{})["id"].(string)
		if seen[id] {
			t.Errorf("rule ID %q appears more than once in the rules array", id)
		}
		seen[id] = true
	}
}
