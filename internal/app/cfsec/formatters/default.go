package formatters

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/liamg/clinch/terminal"
	"github.com/liamg/tml"
)

var severityFormat map[severity.Severity]string

// FormatDefault ...
func FormatDefault(_ io.Writer, results []rules.Result, _ string, options ...FormatterOption) error {
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
	for i, res := range results {
		printResult(res, i, false)
	}

	terminal.PrintErrorf("\n  %d potential problems detected.\n\n", len(results))

	return nil

}

func printResult(res rules.Result, i int, includePassedChecks bool) {
	resultHeader := fmt.Sprintf("  <underline>Result %d</underline>\n", i+1)
	var severity string
	if includePassedChecks && res.Status() == rules.StatusPassed {
		terminal.PrintSuccessf(resultHeader)
		severity = tml.Sprintf("<green>PASSED</green>")
	} else {
		terminal.PrintErrorf(resultHeader)
		severity = severityFormat[res.Rule().Severity]
	}

	_ = tml.Printf(`
  <blue>[</blue>%s<blue>]</blue><blue>[</blue>%s<blue>]</blue> %s
  <blue>%s</blue>

`, res.Rule().LongID(), severity, res.Description(), res.Metadata().Range())

	cfRef := res.Reference().(*parser.CFReference)
	render, err := getFileContent(*cfRef)
	if err != nil {
		fmt.Fprint(os.Stderr, err.Error())
	}

	tml.Println(render)
	fmt.Printf("\n\n")
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

func getFileContent(ref parser.CFReference) (string, error) {
	rng := ref.ResourceRange()

	var resolvedValue string
	prop := ref.ResolvedAttributeValue().(parser.Property)
	hasFailureAttr := prop.IsNotNil()

	content, err := ioutil.ReadFile(rng.GetFilename())
	if err != nil {
		return "", err
	}

	bodyStrings := strings.Split(string(content), "\n")

	var coloured []string
	for i, bodyString := range bodyStrings {
		resolvedValue = ""
		if i >= rng.GetStartLine()-1 && i <= rng.GetEndLine() {
			// TODO: Fix this for json
			if !strings.HasSuffix(rng.GetFilename(), ".json") {
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
