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
	"github.com/aquasecurity/defsec/types"
	"github.com/liamg/clinch/terminal"
	"github.com/liamg/tml"
)

var severityFormat map[severity.Severity]string

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
  
`, res.Rule().LongID(), severity, res.Description(), res.Metadata().Range())

	cfRef := res.Reference().(*parser.CFReference)
	render, err := getFileContent(*cfRef, res.Metadata().Range())
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

func getFileContent(ref parser.CFReference, issueRange types.Range) (string, error) {
	rng := ref.ResourceRange()

	resolvedValue := ""

	content, err := ioutil.ReadFile(rng.GetFilename())
	if err != nil {
		return "", err
	}

	bodyStrings := strings.Split(string(content), "\n")

	for i := issueRange.GetStartLine() - 1; i < issueRange.GetEndLine(); i++ {
		if i == issueRange.GetEndLine()-1 && ref.ResolvedAttributeValue() != nil {
			prop := ref.ResolvedAttributeValue().(parser.Property)
			if prop.IsNotNil() {
				resolvedValue = fmt.Sprintf("[%v]", prop.RawValue())
			}
		}
		bodyStrings[i] = fmt.Sprintf("<red>%s %s</red>", bodyStrings[i], resolvedValue)
	}

	return strings.Join(bodyStrings[rng.GetStartLine()-1:rng.GetEndLine()], "\n"), nil

}
