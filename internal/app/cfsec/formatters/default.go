package formatters

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/resource"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/liamg/clinch/terminal"
	"github.com/liamg/tml"
)

var severityFormat = map[severity.Severity]string{
	severity.Low:      tml.Sprintf("<white>%s</white>", severity.Low),
	severity.Medium:   tml.Sprintf("<yellow>%s</yellow>", severity.Medium),
	severity.High:     tml.Sprintf("<red>%s</red>", severity.High),
	severity.Critical: tml.Sprintf("<bold><red>%s</red></bold>", severity.Critical),
}

func FormatDefault(_ io.Writer, results []rules.Result, _ string) error {

	fmt.Println("")
	for i, res := range results {
		printResult(res, i, false)
	}

	terminal.PrintErrorf("\n  %d potential problems detected.\n\n", len(results))

	return nil

}

func printResult(res rules.Result, i int, includePassedChecks bool) {
	resultHeader := fmt.Sprintf("  <underline>Result %d</underline>\n", i+1)
	var severity string
	//if includePassedChecks && res.Status == result.Passed {
	//terminal.PrintSuccessf(resultHeader)
	//severity = tml.Sprintf("<green>PASSED</green>")
	//} else {
	terminal.PrintErrorf(resultHeader)
	severity = severityFormat[res.Rule().Severity]
	//}

	_ = tml.Printf(`
  <blue>[</blue>%s<blue>]</blue><blue>[</blue>%s<blue>]</blue> %s
  <blue>%s</blue>
  
`, res.Rule().ID, severity, res.Description, res.Metadata().Range())

	cfRef := res.Reference().(*resource.CFReference)

	render, err := cfRef.Resource().Render()
	if err != nil {
		fmt.Fprint(os.Stderr, err.Error())
	}

	highlightRender(render, cfRef.Attribute())

	if res.Rule().Impact != "" {
		_ = tml.Printf("  <white>Impact:     </white><blue>%s</blue>\n", res.Rule().Impact)
	}
	if res.Rule().Resolution != "" {
		_ = tml.Printf("  <white>Resolution: </white><blue>%s</blue>\n", res.Rule().Resolution)
	}
	if len(res.Rule().Links) > 0 {
		_ = tml.Printf("\n  <white>More Info:</white>")
	}
	for _, link := range res.Rule().Links {
		_ = tml.Printf("\n  <blue>- %s </blue>", link)
	}

	fmt.Printf("\n\n")
}

func highlightRender(renderText string, attributeOfInterest string) {

	if attributeOfInterest == "" {
		tml.Println(renderText)
	} else {

		searchRegex, err := regexp.Compile(fmt.Sprintf("%s[\"|:]", attributeOfInterest))
		if err != nil {
			tml.Println(renderText)
		}
		var newLines []string

		lines := strings.Split(renderText, "\n")
		for _, line := range lines {
			if searchRegex.MatchString(line) {
				newLines = append(newLines, fmt.Sprintf("  <red>%s</red>", line))
			} else {
				newLines = append(newLines, fmt.Sprintf("  %s", line))
			}
		}

		tml.Printf(strings.Join(newLines, "\n"))
	}
}
