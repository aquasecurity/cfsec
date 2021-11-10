package result

import (
	"fmt"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
)

type Status string

const (
	Failed  Status = "failed"
	Passed  Status = "passed"
	Ignored Status = "ignored"
)

type LocationBlock struct {
	Filename  string `json:"filepath"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

func (r LocationBlock) String() string {
	if r.EndLine == 0 {
		return r.Filename
	}

	if r.StartLine != r.EndLine {
		return fmt.Sprintf("%s:%d-%d", r.Filename, r.StartLine, r.EndLine)
	}
	return fmt.Sprintf("%s:%d", r.Filename, r.StartLine)
}

// Result is a positive result for a security check. It encapsulates a code unique to the specific check it was raised
// by, a human-readable description and a range
type Result struct {
	AVDID            string            `json:"avd_id"`
	RuleID           string            `json:"rule_id"`
	RuleSummary      string            `json:"rule_description"`
	Impact           string            `json:"impact"`
	Resolution       string            `json:"resolution"`
	Links            []string          `json:"links"`
	Description      string            `json:"description"`
	RangeAnnotation  string            `json:"-"`
	Severity         severity.Severity `json:"severity"`
	Status           rules.Status      `json:"status"`
	Location         LocationBlock     `json:"location"`
	Resource         string            `json:"resource"`
	resolvedProperty parser.Property
}

func (r *Result) GetProperty() parser.Property {
	return r.resolvedProperty
}

func (r *Result) SetProperty(property parser.Property) {
	r.resolvedProperty = property
}
