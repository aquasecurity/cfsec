package formatters

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/cfsec/pkg/result"
	"github.com/aquasecurity/defsec/severity"
	"github.com/liamg/clinch/terminal"
	"github.com/liamg/tml"
)

var severityFormat map[severity.Severity]string

// FormatDefault ...
func FormatDefault(_ io.Writer, results []result.Result, _ string, options ...FormatterOption) error {
	if severityFormat == nil {
		severityFormat = map[severity.Severity]string{
			severity.Low:      tml.Sprintf("<white>%s</white>", severity.Low),
			severity.Medium:   tml.Sprintf("<yellow>%s</yellow>", severity.Medium),
			severity.High:     tml.Sprintf("<red>%s</red>", severity.High),
			severity.Critical: tml.Sprintf("<bold><red>%s</red></bold>", severity.Critical),
			"":                tml.Sprintf("<white>UNKNOWN</white>"),
		}
	}

	fmt.Println("")
	var includePassed bool
	for _, option := range options {
		if option == IncludePassed {
			includePassed = true
		}
	}

	for i, res := range results {
		printResult(res, i, includePassed)
	}

	var failedResults int
	for _, r := range results {
		if r.Status == result.Failed {
			failedResults += 1
		}
	}

	terminal.PrintErrorf("\n  %d potential problems detected.\n\n", failedResults)

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

	render, err := getFileContent(res.Location, res.GetProperty())
	if err != nil {
		fmt.Fprint(os.Stderr, err.Error())
	}

	if res.Status == result.Failed {
		tml.Println(render)
	}
	fmt.Printf("\n\n")
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

func getFileContent(rng result.LocationBlock, prop parser.Property) (string, error) {

	var resolvedValue string
	hasFailureAttr := prop.IsNotNil()

	content, err := ioutil.ReadFile(rng.Filename)
	if err != nil {
		return "", err
	}

	bodyStrings := strings.Split(string(content), "\n")

	var coloured []string
	for i, bodyString := range bodyStrings {
		resolvedValue = ""
		if i >= rng.StartLine-1 && i <= rng.EndLine {
			// TODO: Fix this for json
			if !strings.HasSuffix(rng.Filename, ".json") {
				if prop.IsNotNil() && prop.Range().GetStartLine()-1 == i {
					resolvedValue = fmt.Sprintf("<blue>[%v]</blue>", prop.RawValue())
				}
			}

			if hasFailureAttr {
				if resolvedValue == "" {
					coloured = append(coloured, fmt.Sprintf("<blue>% 5d</blue> | <yellow>%s</yellow>", i, bodyString))
				} else {
					coloured = append(coloured, fmt.Sprintf("<blue>% 5d</blue> | <red>%s    %s</red>", i, bodyString, resolvedValue))
				}
			} else {
				coloured = append(coloured, fmt.Sprintf("<blue>% 5d</blue> | <red>%s</red>", i, bodyString))

			}
		}
	}

	return strings.Join(coloured, "\n"), nil

}
