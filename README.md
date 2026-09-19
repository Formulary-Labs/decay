# decay

Longitudinal compliance drift detector.

```bash
go get github.com/Formulary-Labs/decay
```

## What it does

`decay` compares two program snapshots — a prior cycle and a current cycle — and runs 13 named detection patterns across four categories. It produces a structured report of what changed and why the changes are anomalous.

`decay` does not interpret intent or assign blame. It flags measurements: coverage dropped 8 points, the same finding recurred in A.8, the SOA has not been amended in two cycles despite three new findings. What those measurements mean is left to the analyst.

All patterns are deterministic. Same snapshots produce the same report on every run.

## Input

```go
import "github.com/Formulary-Labs/decay/drift"

report, err := drift.Detect(
    fromSnapshot,  // drift.ProgramSnapshot — the prior cycle
    toSnapshot,    // drift.ProgramSnapshot — the current cycle
)
```

### ProgramSnapshot fields

```go
drift.ProgramSnapshot{
    Cycle:   "2026-Q2",
    RunDate: &runDate,
    Coverage: &drift.CoverageSnapshot{
        EvidencedPct:   74.0,
        ImplementedPct: 82.0,
        GapPct:         18.0,
        Total:          114,
    },
    Findings:         []drift.AuditFinding{...},
    SOA:              &drift.SOASnapshot{Version: "1.3", LastAmended: "2026-06-01", ExceptionCount: 4},
    RiskAssessment:   &drift.RiskAssessmentSnapshot{Version: "2.1", LastAmended: "2026-06-15", RiskCount: 12},
    ControlOwners:    []string{"security-team", "it-ops"},
    SampledFamilies:  []string{"A.5", "A.8", "A.12"},
    DeclaredFamilies: []string{"A.5", "A.6", "A.7", "A.8", "A.9", "A.12"},
}
```

Fields not populated are skipped by the patterns that depend on them. `InputFlags` in the output notes what was unavailable.

## Detection patterns

### Audit coverage anomalies

| Pattern | Severity | Detection |
|---|---|---|
| `PERSISTENT_BLIND_SPOT` | High | Control families appearing in neither cycle's audit sample |
| `SAMPLE_CONCENTRATION` | Medium | Same families sampled in both cycles while others are never sampled |
| `COVERAGE_REGRESSION` | High | Evidenced coverage dropped more than 5 percentage points between cycles |
| `SOA_AUDIT_DIVERGENCE` | Critical | Families declared in scope but never appearing in any audit sample across either cycle |

### Finding and remediation anomalies

| Pattern | Severity | Detection |
|---|---|---|
| `NON_DURABLE_REMEDIATION` | High | A finding closed in the prior cycle recurs in the current cycle |
| `ACCELERATED_CLOSURE` | Medium | Findings closed in the current cycle with no documented remediation timeline |
| `FINDING_RATE_ANOMALY` | Med/Low | Zero findings in prior cycle, >2 in current cycle in the same family (or the reverse) |
| `RECURRENT_FINDING` | High | The same control family has findings in both cycles |
| `REMEDIATION_LANGUAGE_DUPLICATION` | Medium | >70% word overlap between prior and current remediation summaries in the same family |

### Document entropy anomalies

| Pattern | Severity | Detection |
|---|---|---|
| `SOA_STAGNATION` | Medium | SOA not amended between cycles despite new findings in the current cycle |
| `RISK_ASSESSMENT_STAGNATION` | Medium | Risk assessment not amended despite new findings |
| `EXCEPTION_AGING` | Low | Exception count unchanged across both cycles |

### Ownership anomalies

| Pattern | Severity | Detection |
|---|---|---|
| `OWNER_CONCENTRATION` | Medium | A single owner controls ≥50% of declared control families |

## Output

```json
{
  "from_cycle": "2025-Q4",
  "to_cycle": "2026-Q2",
  "generated_at": "2026-09-18T00:00:00Z",
  "findings": [
    {
      "pattern_id": "COVERAGE_REGRESSION",
      "severity": "high",
      "description": "Evidenced coverage fell from 82.0% to 74.0% — a drop of 8 percentage points.",
      "evidence": [
        "from_cycle.coverage.evidenced_pct = 82.0",
        "to_cycle.coverage.evidenced_pct = 74.0"
      ],
      "flags": []
    }
  ],
  "disclaimer": "All findings require validation by a qualified compliance SME before action is taken.",
  "input_flags": []
}
```

`input_flags` lists fields that were absent from the snapshot inputs, so you know which patterns ran with incomplete data.

## When to run it

Run `decay` at the end of each audit cycle to compare the current cycle to the prior one. The output feeds two downstream steps:

- **`specimen`** — convert `NON_DURABLE_REMEDIATION` and `RECURRENT_FINDING` entries into new risk register items tagged `feed_forward`
- **The agent layer** (regimen) — narrate the drift report into a stakeholder communication or QBR section

```bash
decay --from snapshots/2025-Q4.json --to snapshots/2026-Q2.json > drift-report.json
```

## License

Apache License 2.0
