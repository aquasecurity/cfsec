package formatters

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/owenrumney/go-sarif/sarif"
	"io"
)

func FormatSarif(w io.Writer, results []rules.Result, _ string, _ ...FormatterOption) error {
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return err
	}

	run := sarif.NewRun("cfsec", "https://cfsec.dev")
	report.AddRun(run)

	for _, wrappedRes := range results {

		res:= wrappedRes.Flatten()
		if res.Status == rules.StatusPassed {
			continue
		}

		var link string
		if len(res.Links) > 0 {
			link = res.Links[0]
		}
		rule := run.AddRule(res.RuleID).
			WithDescription(res.RuleSummary).
			WithHelp(link)

		message := sarif.NewTextMessage(res.Description)
		region := sarif.NewSimpleRegion(res.Location.StartLine, res.Location.EndLine)
		var level string
		switch res.Severity {
		case severity.None:
			level = "none"
		case severity.Low:
			level = "note"
		case severity.Medium:
			level = "warning"
		case severity.High, severity.Critical:
			level = "error"
		}

		location := sarif.NewPhysicalLocation().
			WithArtifactLocation(sarif.NewSimpleArtifactLocation(res.Location.Filename)).
			WithRegion(region)

		ruleResult := run.AddResult(rule.ID)

		ruleResult.WithMessage(message).
			WithLevel(level).
			WithLocation(sarif.NewLocation().WithPhysicalLocation(location))
	}

	return report.PrettyWrite(w)
}
