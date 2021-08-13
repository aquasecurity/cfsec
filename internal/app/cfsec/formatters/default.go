package formatters

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/result"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/severity"
	"github.com/liamg/clinch/terminal"
	"github.com/liamg/tml"
)

var severityFormat = map[severity.Severity]string{
	severity.Low:      tml.Sprintf("<white>%s</white>", severity.Low),
	severity.Medium:   tml.Sprintf("<yellow>%s</yellow>", severity.Medium),
	severity.High:     tml.Sprintf("<red>%s</red>", severity.High),
	severity.Critical: tml.Sprintf("<bold><red>%s</red></bold>", severity.Critical),
}

func FormatDefault(_ io.Writer, results []result.Result, _ string) error {

	fmt.Println("")
	for i, res := range results {
		printResult(res, i, false)
	}

	terminal.PrintErrorf("\n  %d potential problems detected.\n\n", len(results))

	return nil

}

func printResult(res result.Result, i int, includePassedChecks bool) {
	resultHeader := fmt.Sprintf("  <underline>Result %d</underline>\n", i+1)
	var severity string
	if includePassedChecks && res.Status == result.Passed {
		terminal.PrintSuccessf(resultHeader)
		severity = tml.Sprintf("<green>PASSED</green>")
	} else {
		terminal.PrintErrorf(resultHeader)
		severity = severityFormat[res.Severity]
	}

	_ = tml.Printf(`
  <blue>[</blue>%s<blue>]</blue><blue>[</blue>%s<blue>]</blue> %s
  <blue>%s</blue>
  
`, res.RuleID, severity, res.Description, res.Location)

	render, err := res.Resource().Render()
	if err != nil {
		fmt.Fprint(os.Stderr, err.Error())
	}

	highlightRender(render, res.Attribute)

	if res.LegacyRuleID != "" {
		_ = tml.Printf("  <white>Legacy ID:  </white><blue>%s</blue>\n", res.LegacyRuleID)
	}
	if res.Impact != "" {
		_ = tml.Printf("  <white>Impact:     </white><blue>%s</blue>\n", res.Impact)
	}
	if res.Resolution != "" {
		_ = tml.Printf("  <white>Resolution: </white><blue>%s</blue>\n", res.Resolution)
	}
	if len(res.Links) > 0 {
		_ = tml.Printf("\n  <white>More Info:</white>")
	}
	for _, link := range res.Links {
		_ = tml.Printf("\n  <blue>- %s </blue>", link)
	}

	fmt.Printf("\n\n")
}

func highlightRender(renderText string, attributeOfInterest string) {
	if attributeOfInterest == "" {
		tml.Println(renderText)
	} else {
		var newLines []string

		lines := strings.Split(renderText, "\n")
		for _, line := range lines {
			if strings.Contains(line, attributeOfInterest) {
				newLines = append(newLines, fmt.Sprintf("  <red>%s</red>", line))
			} else {
				newLines = append(newLines, fmt.Sprintf("  %s", line))
			}
		}

		tml.Printf(strings.Join(newLines, "\n"))
	}
}
