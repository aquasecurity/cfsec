package formatters

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"

	"github.com/aquasecurity/defsec/rules"
)

func FormatCSV(w io.Writer, results []rules.Result, _ string, _ ...FormatterOption) error {

	records := [][]string{
		{"file", "start_line", "end_line", "rule_id", "severity", "description", "link", "passed"},
	}

	for _, r := range results {
		res := r.Flatten()
		var link string
		if len(res.Links) > 0 {
			link = res.Links[0]
		}
		records = append(records, []string{
			res.Location.Filename,
			strconv.Itoa(res.Location.StartLine),
			strconv.Itoa(res.Location.EndLine),
			res.RuleID,
			string(res.Severity),
			res.Description,
			link,
			strconv.FormatBool(res.Status == rules.StatusPassed),
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
