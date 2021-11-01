package formatters

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"

	"github.com/aquasecurity/cfsec/pkg/result"
	"github.com/aquasecurity/defsec/rules"
)

// FormatCSV ...
func FormatCSV(w io.Writer, results []result.Result, _ string, _ ...FormatterOption) error {

	records := [][]string{
		{"file", "start_line", "end_line", "rule_id", "severity", "description", "link", "passed"},
	}

	for _, r := range results {
		var link string
		if len(r.Links) > 0 {
			link = r.Links[0]
		}

		records = append(records, []string{
			r.Location.Filename,
			strconv.Itoa(r.Location.StartLine),
			strconv.Itoa(r.Location.EndLine),
			r.RuleID,
			string(r.Severity),
			r.Description,
			link,
			strconv.FormatBool(r.Status == rules.StatusPassed),
		})
	}

	csvWriter := csv.NewWriter(w)

	for _, record := range records {
		if err := csvWriter.Write(record); err != nil {
			return fmt.Errorf("error writing record to csv: %s", err)
		}
	}

	csvWriter.Flush()

	return csvWriter.Error()
}
