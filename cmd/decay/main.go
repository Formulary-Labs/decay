// decay detects longitudinal compliance drift between two program cycle snapshots.
//
// Usage:
//
//	decay --from <from.json> --to <to.json> [--format json|md]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Formulary-Labs/decay/drift"
	"github.com/Formulary-Labs/substrate/exit"
	"github.com/Formulary-Labs/substrate/provenance"
)

const version = "0.1.0"

func main() {
	var (
		fromFlag    = flag.String("from", "", "Path to prior-cycle snapshot JSON (required)")
		toFlag      = flag.String("to", "", "Path to current-cycle snapshot JSON (required)")
		programFlag = flag.String("program", "", "Program slug for provenance logging")
		fmtFlag     = flag.String("format", "json", "Output format: json (default), md")
		versionFlag = flag.Bool("version", false, "Print version and exit")
	)
	flag.Usage = usage
	flag.Parse()

	if *versionFlag {
		fmt.Printf("decay version %s\n", version)
		os.Exit(exit.OK)
	}

	if *fromFlag == "" || *toFlag == "" {
		fmt.Fprintln(os.Stderr, `{"error": "--from and --to are required", "code": 2}`)
		flag.Usage()
		os.Exit(exit.ToolError)
	}

	from, err := drift.Load(*fromFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, `{"error": %q, "code": 2}`+"\n", err.Error())
		os.Exit(exit.ToolError)
	}
	to, err := drift.Load(*toFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, `{"error": %q, "code": 2}`+"\n", err.Error())
		os.Exit(exit.ToolError)
	}

	report := drift.Detect(from, to)

	switch *fmtFlag {
	case "md":
		printMD(report)
	default:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(report) //nolint:errcheck
	}

	if *programFlag != "" {
		_ = provenance.Write("logs/provenance.jsonl", provenance.Entry{
			Spec:        "functions/compliance-entropy-spec.md",
			Output:      *toFlag,
			OutputType:  "other",
			Program:     *programFlag,
			Purpose:     fmt.Sprintf("decay: drift analysis %s → %s, %d findings", from.Cycle, to.Cycle, len(report.Findings)),
			Reusability: provenance.Instance,
			QualityGate: provenance.Pass,
			Tool:        "decay",
			ToolVersion: version,
		})
	}
}

func printMD(r drift.DriftReport) {
	sb := &strings.Builder{}
	fmt.Fprintf(sb, "# Compliance Drift Report: %s → %s\n\n", r.FromCycle, r.ToCycle)
	fmt.Fprintf(sb, "**Generated:** %s  \n", r.GeneratedAt.Format("2006-01-02 15:04 UTC"))
	fmt.Fprintf(sb, "**Findings:** %d\n\n", len(r.Findings))

	if len(r.InputFlags) > 0 {
		fmt.Fprintf(sb, "## Input Flags\n\n")
		for _, f := range r.InputFlags {
			fmt.Fprintf(sb, "- %s\n", f)
		}
		fmt.Fprintln(sb)
	}

	if len(r.Findings) == 0 {
		fmt.Fprintf(sb, "No drift patterns detected between %s and %s.\n\n", r.FromCycle, r.ToCycle)
	} else {
		fmt.Fprintf(sb, "| Pattern | Severity | Description |\n|---|---|---|\n")
		for _, f := range r.Findings {
			fmt.Fprintf(sb, "| %s | %s | %s |\n", f.PatternID, f.Severity, f.Description)
		}
		fmt.Fprintln(sb)
		for _, f := range r.Findings {
			if len(f.Evidence) > 0 || len(f.Flags) > 0 {
				fmt.Fprintf(sb, "### %s\n\n", f.PatternID)
				for _, e := range f.Evidence {
					fmt.Fprintf(sb, "- %s\n", e)
				}
				for _, fl := range f.Flags {
					fmt.Fprintf(sb, "- %s\n", fl)
				}
				fmt.Fprintln(sb)
			}
		}
	}

	fmt.Fprintf(sb, "---\n\n*%s*\n", r.Disclaimer)
	fmt.Print(sb.String())
}

func usage() {
	fmt.Fprintln(os.Stderr, `decay — longitudinal compliance drift detection

Usage:
  decay --from <prior.json> --to <current.json> [flags]

Flags:
  --from string     Path to prior-cycle snapshot JSON (required)
  --to string       Path to current-cycle snapshot JSON (required)
  --program string  Program slug for provenance logging
  --format string   Output format: json (default), md
  --version         Print version and exit

Snapshot JSON format:
  {
    "cycle": "2026-Q2",
    "run_date": "2026-06-30T00:00:00Z",
    "coverage": {"evidenced_pct": 72, "total_controls": 100},
    "sampled_families": ["A.5", "A.8"],
    "declared_families": ["A.5", "A.8", "A.9"],
    "findings": [{"id": "F-001", "control_family": "A.8", "severity": "high"}],
    "soa": {"last_amended": "2026-01-15T00:00:00Z", "exception_count": 2}
  }

Examples:
  decay --from runs/2026-Q2-snapshot.json --to runs/2026-Q3-snapshot.json
  decay --from runs/2026-Q2-snapshot.json --to runs/2026-Q3-snapshot.json --format md
  decay --from q2.json --to q3.json | vital --format md`)
}
