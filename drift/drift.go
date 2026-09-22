// Package drift implements the 13 entropy detection patterns for decay.
//
// Patterns are organised into four categories as defined in
// functions/compliance-entropy-spec.md:
//
//	3.1 Audit Coverage Anomalies  (4 patterns)
//	3.2 Finding/Remediation       (5 patterns)
//	3.3 Document Entropy          (3 patterns)
//	3.4 Ownership                 (1 pattern)
//
// decay operates on two ProgramSnapshot values — a "from" and a "to" cycle —
// and returns a DriftReport containing the findings for all triggered patterns.
//
// This is a deterministic computation tool. It flags observations; it does NOT
// interpret intent or draw causal conclusions — that is left to the analyst.
package drift

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"
	"time"
)

// PatternID is one of the 13 named detection patterns.
type PatternID string

//nolint:revive // PatternID constants are self-documenting string identifiers.
const (
	// 3.1 Audit Coverage Anomalies
	PersistentBlindSpot PatternID = "PERSISTENT_BLIND_SPOT"
	SampleConcentration PatternID = "SAMPLE_CONCENTRATION"
	CoverageRegression  PatternID = "COVERAGE_REGRESSION"
	SOAAuditDivergence  PatternID = "SOA_AUDIT_DIVERGENCE"

	// 3.2 Finding and Remediation Anomalies
	NonDurableRemediation          PatternID = "NON_DURABLE_REMEDIATION"
	AcceleratedClosure             PatternID = "ACCELERATED_CLOSURE"
	FindingRateAnomaly             PatternID = "FINDING_RATE_ANOMALY"
	RecurrentFinding               PatternID = "RECURRENT_FINDING"
	RemediationLanguageDuplication PatternID = "REMEDIATION_LANGUAGE_DUPLICATION"

	// 3.3 Document Entropy Anomalies
	SOAStagnation            PatternID = "SOA_STAGNATION"
	RiskAssessmentStagnation PatternID = "RISK_ASSESSMENT_STAGNATION"
	ExceptionAging           PatternID = "EXCEPTION_AGING"

	// 3.4 Ownership Anomalies
	OwnerConcentration PatternID = "OWNER_CONCENTRATION"
)

// Severity mirrors the spec severity levels.
type Severity string

//nolint:revive // Severity constants are self-documenting.
const (
	Critical Severity = "critical" // likely audit finding or cert failure
	High     Severity = "high"     // auditor likely to flag
	Medium   Severity = "medium"   // auditor may ask about
	Low      Severity = "low"      // best practice gap
)

// Finding is a single triggered pattern with evidence.
type Finding struct {
	PatternID   PatternID `json:"pattern_id"`
	Severity    Severity  `json:"severity"`
	Description string    `json:"description"`
	Evidence    []string  `json:"evidence,omitempty"`
	Flags       []string  `json:"flags,omitempty"` // LOW_CONFIDENCE_MAPPING etc.
}

// DriftReport is the full output of a decay run.
type DriftReport struct { //nolint:revive // stutter is intentional
	FromCycle   string    `json:"from_cycle"`
	ToCycle     string    `json:"to_cycle"`
	GeneratedAt time.Time `json:"generated_at"`
	Findings    []Finding `json:"findings"`
	Disclaimer  string    `json:"disclaimer"`

	// Input data availability.
	InputFlags []string `json:"input_flags,omitempty"`
}

// ProgramSnapshot is the minimal program state decay reads.
// It accepts the prompt-repo run JSON shape, plus fields decay adds for
// longitudinal analysis (prior-cycle audit data).
type ProgramSnapshot struct {
	Cycle   string     `json:"cycle"` // e.g. "2026-Q2"
	RunDate *time.Time `json:"run_date,omitempty"`

	// Control coverage.
	Coverage *CoverageSnapshot `json:"coverage,omitempty"`

	// Audit findings from this cycle.
	Findings []AuditFinding `json:"findings,omitempty"`

	// SOA metadata.
	SOA *SOASnapshot `json:"soa,omitempty"`

	// Risk assessment metadata.
	RiskAssessment *RiskAssessmentSnapshot `json:"risk_assessment,omitempty"`

	// Control owners.
	ControlOwners []ControlOwner `json:"control_owners,omitempty"`

	// Sampled control families this cycle.
	SampledFamilies []string `json:"sampled_families,omitempty"`

	// All declared control families (from SOA/catalog).
	DeclaredFamilies []string `json:"declared_families,omitempty"`
}

// CoverageSnapshot is point-in-time coverage percentages.
type CoverageSnapshot struct {
	EvidencedPct   float64 `json:"evidenced_pct"`
	ImplementedPct float64 `json:"implemented_pct"`
	GapPct         float64 `json:"gap_pct"`
	TotalControls  int     `json:"total_controls"`
}

// AuditFinding is a single finding from an audit cycle.
type AuditFinding struct {
	ID                 string     `json:"id"`
	ControlFamily      string     `json:"control_family"`
	Severity           string     `json:"severity"`
	OpenedAt           *time.Time `json:"opened_at,omitempty"`
	ClosedAt           *time.Time `json:"closed_at,omitempty"`
	ReopenedAt         *time.Time `json:"reopened_at,omitempty"`
	RemediationSummary string     `json:"remediation_summary,omitempty"`
}

// SOASnapshot captures SOA versioning metadata.
type SOASnapshot struct {
	Version        string     `json:"version,omitempty"`
	LastAmended    *time.Time `json:"last_amended,omitempty"`
	ExceptionCount int        `json:"exception_count"`
}

// RiskAssessmentSnapshot captures RA versioning metadata.
type RiskAssessmentSnapshot struct {
	Version     string     `json:"version,omitempty"`
	LastAmended *time.Time `json:"last_amended,omitempty"`
	RiskCount   int        `json:"risk_count"`
}

// ControlOwner maps a control family to an owner.
type ControlOwner struct {
	Family string `json:"family"`
	Owner  string `json:"owner"`
}

// Load reads a ProgramSnapshot from a JSON file.
func Load(path string) (*ProgramSnapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading snapshot %q: %w", path, err)
	}
	var s ProgramSnapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parsing snapshot %q: %w", path, err)
	}
	return &s, nil
}

const disclaimer = "All findings require validation by a qualified compliance SME before action is taken."

// Detect runs all 13 detection patterns and returns a DriftReport.
func Detect(from, to *ProgramSnapshot) DriftReport {
	r := DriftReport{
		FromCycle:   from.Cycle,
		ToCycle:     to.Cycle,
		GeneratedAt: time.Now().UTC(),
		Disclaimer:  disclaimer,
	}

	// Validate inputs.
	if from.Cycle == "" || to.Cycle == "" {
		r.InputFlags = append(r.InputFlags, "[DATA NEEDED: cycle] — both snapshots must have a cycle field (e.g. 2026-Q2)")
	}

	// 3.1 Audit Coverage Anomalies.
	r.Findings = append(r.Findings, detectPersistentBlindSpot(from, to)...)
	r.Findings = append(r.Findings, detectSampleConcentration(from, to)...)
	r.Findings = append(r.Findings, detectCoverageRegression(from, to)...)
	r.Findings = append(r.Findings, detectSOAAuditDivergence(from, to)...)

	// 3.2 Finding and Remediation Anomalies.
	r.Findings = append(r.Findings, detectNonDurableRemediation(from, to)...)
	r.Findings = append(r.Findings, detectAcceleratedClosure(from, to)...)
	r.Findings = append(r.Findings, detectFindingRateAnomaly(from, to)...)
	r.Findings = append(r.Findings, detectRecurrentFinding(from, to)...)
	r.Findings = append(r.Findings, detectRemediationLanguageDuplication(from, to)...)

	// 3.3 Document Entropy.
	r.Findings = append(r.Findings, detectSOAStagnation(from, to)...)
	r.Findings = append(r.Findings, detectRiskAssessmentStagnation(from, to)...)
	r.Findings = append(r.Findings, detectExceptionAging(from, to)...)

	// 3.4 Ownership.
	r.Findings = append(r.Findings, detectOwnerConcentration(from, to)...)

	return r
}

// --- 3.1 Audit Coverage Anomalies ---

func detectPersistentBlindSpot(from, to *ProgramSnapshot) []Finding {
	if len(from.SampledFamilies) == 0 || len(to.SampledFamilies) == 0 {
		return nil
	}
	fromSet := setOf(from.SampledFamilies)
	toSet := setOf(to.SampledFamilies)
	allDeclared := union(setOf(from.DeclaredFamilies), setOf(to.DeclaredFamilies))
	if len(allDeclared) == 0 {
		allDeclared = union(fromSet, toSet)
	}

	var blind []string
	for family := range allDeclared {
		if !fromSet[family] && !toSet[family] {
			blind = append(blind, family)
		}
	}
	if len(blind) == 0 {
		return nil
	}
	return []Finding{{
		PatternID:   PersistentBlindSpot,
		Severity:    High,
		Description: fmt.Sprintf("%d control famil(ies) were not sampled in either the %s or %s audit cycle", len(blind), from.Cycle, to.Cycle),
		Evidence:    blind,
	}}
}

func detectSampleConcentration(from, to *ProgramSnapshot) []Finding {
	if len(from.SampledFamilies) == 0 || len(to.SampledFamilies) == 0 {
		return nil
	}
	fromSet := setOf(from.SampledFamilies)
	toSet := setOf(to.SampledFamilies)
	// Families sampled in both cycles while others declared were not.
	repeated := intersection(fromSet, toSet)
	allDeclared := union(setOf(from.DeclaredFamilies), setOf(to.DeclaredFamilies))
	if len(allDeclared) == 0 {
		return nil
	}
	neverSampled := 0
	for f := range allDeclared {
		if !fromSet[f] && !toSet[f] {
			neverSampled++
		}
	}
	if len(repeated) == 0 || neverSampled == 0 {
		return nil
	}
	return []Finding{{
		PatternID:   SampleConcentration,
		Severity:    Medium,
		Description: fmt.Sprintf("%d control famil(ies) sampled in both cycles while %d declared famil(ies) were never sampled", len(repeated), neverSampled),
	}}
}

func detectCoverageRegression(from, to *ProgramSnapshot) []Finding {
	if from.Coverage == nil || to.Coverage == nil {
		return nil
	}
	delta := to.Coverage.EvidencedPct - from.Coverage.EvidencedPct
	if delta >= -5 { // threshold: 5 pp regression
		return nil
	}
	return []Finding{{
		PatternID:   CoverageRegression,
		Severity:    High,
		Description: fmt.Sprintf("Evidenced coverage regressed from %.0f%% (%s) to %.0f%% (%s) — %.0f pp decline", from.Coverage.EvidencedPct, from.Cycle, to.Coverage.EvidencedPct, to.Cycle, math.Abs(delta)),
	}}
}

func detectSOAAuditDivergence(from, to *ProgramSnapshot) []Finding {
	declared := setOf(to.DeclaredFamilies)
	if len(declared) == 0 {
		return nil
	}
	sampled := union(setOf(from.SampledFamilies), setOf(to.SampledFamilies))
	var never []string
	for f := range declared {
		if !sampled[f] {
			never = append(never, f)
		}
	}
	if len(never) == 0 {
		return nil
	}
	return []Finding{{
		PatternID:   SOAAuditDivergence,
		Severity:    Critical,
		Description: fmt.Sprintf("%d control famil(ies) are declared in scope (SOA) but have never appeared in an audit sample", len(never)),
		Evidence:    never,
	}}
}

// --- 3.2 Finding and Remediation Anomalies ---

func detectNonDurableRemediation(from, to *ProgramSnapshot) []Finding {
	// Finding in from that was closed, appears again in to.
	fromFamilies := map[string]bool{}
	for _, f := range from.Findings {
		if f.ClosedAt != nil {
			fromFamilies[f.ControlFamily] = true
		}
	}
	if len(fromFamilies) == 0 {
		return nil
	}
	var recurred []string
	for _, f := range to.Findings {
		if fromFamilies[f.ControlFamily] {
			recurred = append(recurred, fmt.Sprintf("%s (family: %s)", f.ID, f.ControlFamily))
		}
	}
	if len(recurred) == 0 {
		return nil
	}
	return []Finding{{
		PatternID:   NonDurableRemediation,
		Severity:    High,
		Description: fmt.Sprintf("%d finding(s) recurred in %s after being closed in %s", len(recurred), to.Cycle, from.Cycle),
		Evidence:    recurred,
	}}
}

func detectAcceleratedClosure(from, to *ProgramSnapshot) []Finding {
	// Findings closed very quickly (within the same cycle they were opened).
	// Threshold: opened and closed within the same cycle snapshot.
	if len(to.Findings) == 0 {
		return nil
	}
	var rapid []string
	for _, f := range to.Findings {
		if f.OpenedAt == nil || f.ClosedAt == nil {
			continue
		}
		days := f.ClosedAt.Sub(*f.OpenedAt).Hours() / 24
		if days >= 0 && days <= 7 {
			rapid = append(rapid, fmt.Sprintf("%s closed in %.0fd (opened %s, closed %s)", f.ID, days, f.OpenedAt.Format("2006-01-02"), f.ClosedAt.Format("2006-01-02")))
		}
	}
	_ = from
	if len(rapid) == 0 {
		return nil
	}
	return []Finding{{
		PatternID:   AcceleratedClosure,
		Severity:    Medium,
		Description: fmt.Sprintf("%d finding(s) in %s were closed within 7 days of being opened — verify closures are substantive, not administrative", len(rapid), to.Cycle),
		Evidence:    rapid,
		Flags:       []string{"[INFERRED] — rapid closure may indicate genuine fix or documentation-only closure; review remediation evidence"},
	}}
}

func detectFindingRateAnomaly(from, to *ProgramSnapshot) []Finding {
	fromRate := familyFindingCounts(from.Findings)
	toRate := familyFindingCounts(to.Findings)
	all := union(keys(fromRate), keys(toRate))
	var findings []Finding
	for family := range all {
		f := fromRate[family]
		t := toRate[family]
		if f == 0 && t > 2 {
			findings = append(findings, Finding{
				PatternID:   FindingRateAnomaly,
				Severity:    Medium,
				Description: fmt.Sprintf("Finding rate spike in %q: 0 findings in %s, %d in %s", family, from.Cycle, t, to.Cycle),
			})
		} else if f > 0 && t == 0 {
			findings = append(findings, Finding{
				PatternID:   FindingRateAnomaly,
				Severity:    Low,
				Description: fmt.Sprintf("Finding rate drop to zero in %q: %d in %s, 0 in %s — verify whether controls improved or coverage reduced", family, f, from.Cycle, to.Cycle),
				Flags:       []string{"[INFERRED] — zero findings may indicate gap in audit sampling, not absence of issues"},
			})
		}
	}
	return findings
}

func detectRecurrentFinding(from, to *ProgramSnapshot) []Finding {
	fromFamilies := familyFindingCounts(from.Findings)
	toFamilies := familyFindingCounts(to.Findings)
	var recurring []string
	for family := range fromFamilies {
		if toFamilies[family] > 0 {
			recurring = append(recurring, family)
		}
	}
	if len(recurring) == 0 {
		return nil
	}
	return []Finding{{
		PatternID:   RecurrentFinding,
		Severity:    High,
		Description: fmt.Sprintf("%d control famil(ies) have findings in both %s and %s — review remediation durability", len(recurring), from.Cycle, to.Cycle),
		Evidence:    recurring,
	}}
}

func detectRemediationLanguageDuplication(from, to *ProgramSnapshot) []Finding {
	if len(from.Findings) == 0 || len(to.Findings) == 0 {
		return nil
	}
	var dupes []string
	for _, tf := range to.Findings {
		if tf.RemediationSummary == "" {
			continue
		}
		for _, ff := range from.Findings {
			if ff.RemediationSummary == "" {
				continue
			}
			if tf.ControlFamily == ff.ControlFamily &&
				similarText(tf.RemediationSummary, ff.RemediationSummary) {
				dupes = append(dupes, fmt.Sprintf("%s (same family as %s, similar remediation)", tf.ID, ff.ID))
				break
			}
		}
	}
	if len(dupes) == 0 {
		return nil
	}
	return []Finding{{
		PatternID:   RemediationLanguageDuplication,
		Severity:    Medium,
		Description: fmt.Sprintf("%d finding(s) in %s have remediation text near-identical to %s closures in the same control family", len(dupes), to.Cycle, from.Cycle),
		Evidence:    dupes,
	}}
}

// --- 3.3 Document Entropy Anomalies ---

func detectSOAStagnation(from, to *ProgramSnapshot) []Finding {
	if from.SOA == nil || to.SOA == nil {
		return nil
	}
	if from.SOA.LastAmended == nil || to.SOA.LastAmended == nil {
		return nil
	}
	if from.SOA.LastAmended.Equal(*to.SOA.LastAmended) && len(to.Findings) > 0 {
		return []Finding{{
			PatternID:   SOAStagnation,
			Severity:    Medium,
			Description: fmt.Sprintf("SOA was not amended between %s and %s despite %d findings in %s", from.Cycle, to.Cycle, len(to.Findings), to.Cycle),
		}}
	}
	return nil
}

func detectRiskAssessmentStagnation(from, to *ProgramSnapshot) []Finding {
	if from.RiskAssessment == nil || to.RiskAssessment == nil {
		return nil
	}
	if from.RiskAssessment.LastAmended == nil || to.RiskAssessment.LastAmended == nil {
		return nil
	}
	if from.RiskAssessment.LastAmended.Equal(*to.RiskAssessment.LastAmended) && len(to.Findings) > 0 {
		return []Finding{{
			PatternID:   RiskAssessmentStagnation,
			Severity:    Medium,
			Description: fmt.Sprintf("Risk assessment was not amended between %s and %s despite %d findings in %s", from.Cycle, to.Cycle, len(to.Findings), to.Cycle),
		}}
	}
	return nil
}

func detectExceptionAging(from, to *ProgramSnapshot) []Finding {
	if from.SOA == nil || to.SOA == nil {
		return nil
	}
	// If exception count is unchanged across cycles and remains > 0, flag.
	if from.SOA.ExceptionCount > 0 && from.SOA.ExceptionCount == to.SOA.ExceptionCount {
		return []Finding{{
			PatternID:   ExceptionAging,
			Severity:    Low,
			Description: fmt.Sprintf("%d exception(s) in SOA have not changed between %s and %s — verify they have been formally re-accepted", from.SOA.ExceptionCount, from.Cycle, to.Cycle),
		}}
	}
	return nil
}

// --- 3.4 Ownership Anomalies ---

func detectOwnerConcentration(from, to *ProgramSnapshot) []Finding {
	_ = from
	if len(to.ControlOwners) < 3 {
		return nil // not enough data
	}
	ownerCounts := map[string]int{}
	for _, co := range to.ControlOwners {
		ownerCounts[co.Owner]++
	}
	total := len(to.ControlOwners)
	var concentrated []string
	for owner, count := range ownerCounts {
		pct := float64(count) / float64(total) * 100
		if pct >= 50 {
			concentrated = append(concentrated, fmt.Sprintf("%s owns %.0f%% of control families (%d/%d)", owner, pct, count, total))
		}
	}
	if len(concentrated) == 0 {
		return nil
	}
	return []Finding{{
		PatternID:   OwnerConcentration,
		Severity:    Medium,
		Description: "Owner concentration detected — single owner controls ≥50% of families",
		Evidence:    concentrated,
	}}
}

// --- helpers ---

func setOf(ss []string) map[string]bool {
	m := map[string]bool{}
	for _, s := range ss {
		m[s] = true
	}
	return m
}

func union(a, b map[string]bool) map[string]bool {
	m := map[string]bool{}
	for k := range a {
		m[k] = true
	}
	for k := range b {
		m[k] = true
	}
	return m
}

func intersection(a, b map[string]bool) map[string]bool {
	m := map[string]bool{}
	for k := range a {
		if b[k] {
			m[k] = true
		}
	}
	return m
}

func keys(m map[string]int) map[string]bool {
	out := map[string]bool{}
	for k := range m {
		out[k] = true
	}
	return out
}

func familyFindingCounts(findings []AuditFinding) map[string]int {
	m := map[string]int{}
	for _, f := range findings {
		m[f.ControlFamily]++
	}
	return m
}

// similarText returns true if two strings share >70% of their words.
func similarText(a, b string) bool {
	if a == b {
		return true
	}
	aWords := setOf(strings.Fields(strings.ToLower(a)))
	bWords := setOf(strings.Fields(strings.ToLower(b)))
	if len(aWords) == 0 || len(bWords) == 0 {
		return false
	}
	shared := 0
	for w := range aWords {
		if bWords[w] {
			shared++
		}
	}
	maxLen := len(aWords)
	if len(bWords) > maxLen {
		maxLen = len(bWords)
	}
	return float64(shared)/float64(maxLen) >= 0.7
}
