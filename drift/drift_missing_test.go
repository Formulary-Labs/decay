package drift_test

import (
	"testing"
	"time"

	"github.com/Formulary-Labs/decay/drift"
)

// TestDetect_sampleConcentration verifies that families sampled in both cycles
// while other declared families are never sampled triggers SAMPLE_CONCENTRATION.
func TestDetect_sampleConcentration(t *testing.T) {
	from := &drift.ProgramSnapshot{
		Cycle:            "2026-Q1",
		SampledFamilies:  []string{"A.5"},
		DeclaredFamilies: []string{"A.5", "A.8", "A.9"},
	}
	to := &drift.ProgramSnapshot{
		Cycle:            "2026-Q2",
		SampledFamilies:  []string{"A.5"},
		DeclaredFamilies: []string{"A.5", "A.8", "A.9"},
	}
	report := drift.Detect(from, to)
	if !findingExists(report, drift.SampleConcentration) {
		t.Error("expected SAMPLE_CONCENTRATION finding")
	}
}

// TestDetect_acceleratedClosure verifies that findings closed within 7 days of
// opening trigger ACCELERATED_CLOSURE.
func TestDetect_acceleratedClosure(t *testing.T) {
	opened := makeTime("2026-06-01")
	closed := makeTime("2026-06-04") // 3 days
	from := &drift.ProgramSnapshot{Cycle: "2026-Q1"}
	to := &drift.ProgramSnapshot{
		Cycle: "2026-Q2",
		Findings: []drift.AuditFinding{
			{ID: "F-001", ControlFamily: "A.8", OpenedAt: opened, ClosedAt: closed},
		},
	}
	report := drift.Detect(from, to)
	if !findingExists(report, drift.AcceleratedClosure) {
		t.Error("expected ACCELERATED_CLOSURE for F-001 closed in 3 days")
	}
}

// TestDetect_acceleratedClosure_notTriggered verifies that a finding closed
// after 45 days does NOT trigger ACCELERATED_CLOSURE.
func TestDetect_acceleratedClosure_notTriggered(t *testing.T) {
	opened := makeTime("2026-01-01")
	closed := makeTime("2026-02-15") // 45 days
	from := &drift.ProgramSnapshot{Cycle: "2026-Q1"}
	to := &drift.ProgramSnapshot{
		Cycle: "2026-Q2",
		Findings: []drift.AuditFinding{
			{ID: "F-001", ControlFamily: "A.8", OpenedAt: opened, ClosedAt: closed},
		},
	}
	report := drift.Detect(from, to)
	if findingExists(report, drift.AcceleratedClosure) {
		t.Error("unexpected ACCELERATED_CLOSURE for finding closed in 45 days")
	}
}

// TestDetect_findingRateAnomaly verifies that a spike (0→3) triggers
// FINDING_RATE_ANOMALY.
func TestDetect_findingRateAnomaly(t *testing.T) {
	from := &drift.ProgramSnapshot{Cycle: "2026-Q1"}
	to := &drift.ProgramSnapshot{
		Cycle: "2026-Q2",
		Findings: []drift.AuditFinding{
			{ID: "F-001", ControlFamily: "A.8"},
			{ID: "F-002", ControlFamily: "A.8"},
			{ID: "F-003", ControlFamily: "A.8"},
		},
	}
	report := drift.Detect(from, to)
	if !findingExists(report, drift.FindingRateAnomaly) {
		t.Error("expected FINDING_RATE_ANOMALY for 0→3 spike in A.8")
	}
}

// TestDetect_recurrentFinding verifies that a family with findings in both
// cycles triggers RECURRENT_FINDING.
func TestDetect_recurrentFinding(t *testing.T) {
	from := &drift.ProgramSnapshot{
		Cycle: "2026-Q1",
		Findings: []drift.AuditFinding{
			{ID: "F-001", ControlFamily: "A.8"},
		},
	}
	to := &drift.ProgramSnapshot{
		Cycle: "2026-Q2",
		Findings: []drift.AuditFinding{
			{ID: "F-002", ControlFamily: "A.8"},
		},
	}
	report := drift.Detect(from, to)
	if !findingExists(report, drift.RecurrentFinding) {
		t.Error("expected RECURRENT_FINDING for A.8 in both cycles")
	}
}

// TestDetect_remediationLanguageDuplication verifies that near-identical
// remediation text in the same family across cycles triggers
// REMEDIATION_LANGUAGE_DUPLICATION.
func TestDetect_remediationLanguageDuplication(t *testing.T) {
	text := "Enforce MFA on all admin accounts using Okta policies and conduct quarterly access reviews."
	from := &drift.ProgramSnapshot{
		Cycle: "2026-Q1",
		Findings: []drift.AuditFinding{
			{ID: "F-001", ControlFamily: "A.9", RemediationSummary: text},
		},
	}
	to := &drift.ProgramSnapshot{
		Cycle: "2026-Q2",
		Findings: []drift.AuditFinding{
			{ID: "F-002", ControlFamily: "A.9", RemediationSummary: text},
		},
	}
	report := drift.Detect(from, to)
	if !findingExists(report, drift.RemediationLanguageDuplication) {
		t.Error("expected REMEDIATION_LANGUAGE_DUPLICATION for identical remediation text")
	}
}

// TestDetect_riskAssessmentStagnation verifies that an unchanged risk
// assessment with new findings triggers RISK_ASSESSMENT_STAGNATION.
func TestDetect_riskAssessmentStagnation(t *testing.T) {
	amended := makeTime("2026-01-15")
	from := &drift.ProgramSnapshot{
		Cycle:          "2026-Q1",
		RiskAssessment: &drift.RiskAssessmentSnapshot{LastAmended: amended},
	}
	to := &drift.ProgramSnapshot{
		Cycle:          "2026-Q2",
		RiskAssessment: &drift.RiskAssessmentSnapshot{LastAmended: amended},
		Findings: []drift.AuditFinding{
			{ID: "F-001", ControlFamily: "A.5"},
		},
	}
	report := drift.Detect(from, to)
	if !findingExists(report, drift.RiskAssessmentStagnation) {
		t.Error("expected RISK_ASSESSMENT_STAGNATION when RA unchanged despite new findings")
	}
}

// Ensure makeTime is used in at least one test to satisfy the import.
var _ = time.Now
