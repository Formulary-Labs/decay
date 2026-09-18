package drift_test

import (
	"testing"
	"time"

	"github.com/Formulary-Labs/decay/drift"
)

func makeTime(s string) *time.Time {
	t, _ := time.Parse("2006-01-02", s)
	return &t
}

func TestDetect_coverageRegression(t *testing.T) {
	from := &drift.ProgramSnapshot{
		Cycle:    "2026-Q1",
		Coverage: &drift.CoverageSnapshot{EvidencedPct: 80, TotalControls: 100},
	}
	to := &drift.ProgramSnapshot{
		Cycle:    "2026-Q2",
		Coverage: &drift.CoverageSnapshot{EvidencedPct: 65, TotalControls: 100},
	}
	report := drift.Detect(from, to)
	if !findingExists(report, drift.CoverageRegression) {
		t.Error("expected COVERAGE_REGRESSION finding")
	}
}

func TestDetect_persistentBlindSpot(t *testing.T) {
	from := &drift.ProgramSnapshot{
		Cycle:            "2026-Q1",
		SampledFamilies:  []string{"A.5", "A.8"},
		DeclaredFamilies: []string{"A.5", "A.8", "A.9", "A.10"},
	}
	to := &drift.ProgramSnapshot{
		Cycle:            "2026-Q2",
		SampledFamilies:  []string{"A.5", "A.8"},
		DeclaredFamilies: []string{"A.5", "A.8", "A.9", "A.10"},
	}
	report := drift.Detect(from, to)
	if !findingExists(report, drift.PersistentBlindSpot) {
		t.Error("expected PERSISTENT_BLIND_SPOT finding for A.9 and A.10")
	}
}

func TestDetect_soaAuditDivergence(t *testing.T) {
	from := &drift.ProgramSnapshot{
		Cycle:            "2026-Q1",
		SampledFamilies:  []string{"A.5"},
		DeclaredFamilies: []string{"A.5", "A.9"},
	}
	to := &drift.ProgramSnapshot{
		Cycle:            "2026-Q2",
		SampledFamilies:  []string{"A.5"},
		DeclaredFamilies: []string{"A.5", "A.9"},
	}
	report := drift.Detect(from, to)
	if !findingExists(report, drift.SOAAuditDivergence) {
		t.Error("expected SOA_AUDIT_DIVERGENCE for A.9")
	}
}

func TestDetect_nonDurableRemediation(t *testing.T) {
	closed := makeTime("2026-03-01")
	from := &drift.ProgramSnapshot{
		Cycle: "2026-Q1",
		Findings: []drift.AuditFinding{
			{ID: "F-001", ControlFamily: "A.8", Severity: "high", ClosedAt: closed},
		},
	}
	to := &drift.ProgramSnapshot{
		Cycle: "2026-Q2",
		Findings: []drift.AuditFinding{
			{ID: "F-002", ControlFamily: "A.8", Severity: "high"},
		},
	}
	report := drift.Detect(from, to)
	if !findingExists(report, drift.NonDurableRemediation) {
		t.Error("expected NON_DURABLE_REMEDIATION finding")
	}
}

func TestDetect_soaStagnation(t *testing.T) {
	amended := makeTime("2025-12-01")
	from := &drift.ProgramSnapshot{
		Cycle: "2026-Q1",
		SOA:   &drift.SOASnapshot{LastAmended: amended, ExceptionCount: 2},
	}
	to := &drift.ProgramSnapshot{
		Cycle: "2026-Q2",
		SOA:   &drift.SOASnapshot{LastAmended: amended, ExceptionCount: 2},
		Findings: []drift.AuditFinding{
			{ID: "F-001", ControlFamily: "A.8", Severity: "medium"},
		},
	}
	report := drift.Detect(from, to)
	if !findingExists(report, drift.SOAStagnation) {
		t.Error("expected SOA_STAGNATION finding")
	}
}

func TestDetect_exceptionAging(t *testing.T) {
	from := &drift.ProgramSnapshot{
		Cycle: "2026-Q1",
		SOA:   &drift.SOASnapshot{ExceptionCount: 3},
	}
	to := &drift.ProgramSnapshot{
		Cycle: "2026-Q2",
		SOA:   &drift.SOASnapshot{ExceptionCount: 3},
	}
	report := drift.Detect(from, to)
	if !findingExists(report, drift.ExceptionAging) {
		t.Error("expected EXCEPTION_AGING finding")
	}
}

func TestDetect_ownerConcentration(t *testing.T) {
	from := &drift.ProgramSnapshot{Cycle: "2026-Q1"}
	to := &drift.ProgramSnapshot{
		Cycle: "2026-Q2",
		ControlOwners: []drift.ControlOwner{
			{Family: "A.5", Owner: "alice"},
			{Family: "A.8", Owner: "alice"},
			{Family: "A.9", Owner: "alice"},
			{Family: "A.10", Owner: "bob"},
		},
	}
	report := drift.Detect(from, to)
	if !findingExists(report, drift.OwnerConcentration) {
		t.Error("expected OWNER_CONCENTRATION finding (alice owns 3/4)")
	}
}

func TestDetect_noFindings(t *testing.T) {
	from := &drift.ProgramSnapshot{
		Cycle:            "2026-Q1",
		SampledFamilies:  []string{"A.5", "A.8"},
		DeclaredFamilies: []string{"A.5", "A.8"},
		Coverage:         &drift.CoverageSnapshot{EvidencedPct: 75, TotalControls: 100},
	}
	to := &drift.ProgramSnapshot{
		Cycle:            "2026-Q2",
		SampledFamilies:  []string{"A.5", "A.8"},
		DeclaredFamilies: []string{"A.5", "A.8"},
		Coverage:         &drift.CoverageSnapshot{EvidencedPct: 78, TotalControls: 100},
	}
	report := drift.Detect(from, to)
	// Only patterns that would trigger should have findings.
	// With all families sampled and coverage improving, no coverage findings.
	hasCoverageRegression := findingExists(report, drift.CoverageRegression)
	hasPBS := findingExists(report, drift.PersistentBlindSpot)
	if hasCoverageRegression {
		t.Error("unexpected COVERAGE_REGRESSION")
	}
	if hasPBS {
		t.Error("unexpected PERSISTENT_BLIND_SPOT")
	}
}

func findingExists(r drift.DriftReport, id drift.PatternID) bool {
	for _, f := range r.Findings {
		if f.PatternID == id {
			return true
		}
	}
	return false
}
