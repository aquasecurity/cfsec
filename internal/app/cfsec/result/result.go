package result

import (
	"fmt"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/resource"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/severity"
)

// Result is a positive result for a security check. It encapsulates a code unique to the specific check it was raised
// by, a human-readable description and a range
type Result struct {
	RuleID       string            `json:"rule_id"`
	LegacyRuleID string            `json:"legacy_rule_id"`
	RuleSummary  string            `json:"rule_description"`
	Impact       string            `json:"impact"`
	Resolution   string            `json:"resolution"`
	Links        []string          `json:"links"`
	Description  string            `json:"description"`
	Attribute    string            `json:"attribute"`
	Severity     severity.Severity `json:"severity"`
	Status       Status            `json:"status"`
	// Location        block.Range       `json:"location"`
	blocks   resource.Resources
	Location string `json:"location"`
	// attribute       block.Attribute
}

type Status string

const (
	Failed  Status = "failed"
	Passed  Status = "passed"
	Ignored Status = "ignored"
)

func New(resourceBlock resource.Resource) *Result {
	result := &Result{
		Status: Failed,
		blocks: []resource.Resource{resourceBlock},
	}
	return result
}

func (r *Result) Passed() bool {
	return r.Status == Passed
}

func (r *Result) Blocks() resource.Resources {
	return r.blocks
}

func (r *Result) Resource() resource.Resource {
	return r.blocks[0]
}

func (r *Result) HashCode() string {
	var hash string
	for _, block := range r.blocks {
		hash += "!" + block.Type()
	}
	return fmt.Sprintf("%s:%s", hash, r.RuleID)
}

func (r *Result) WithRuleID(id string) *Result {
	r.RuleID = id
	return r
}

func (r *Result) WithLegacyRuleID(id string) *Result {
	r.LegacyRuleID = id
	return r
}

func (r *Result) WithRuleSummary(description string) *Result {
	r.RuleSummary = description
	return r
}

func (r *Result) WithImpact(impact string) *Result {
	r.Impact = impact
	return r
}

func (r *Result) WithResolution(resolution string) *Result {
	r.Resolution = resolution
	return r
}

func (r *Result) WithLink(link string) *Result {
	r.Links = append(r.Links, link)
	return r
}

func (r *Result) WithLinks(links []string) *Result {
	r.Links = links
	return r
}

func (r *Result) WithLocation(location string) *Result {
	r.Location = location
	return r
}

func (r *Result) WithBlock(block resource.Resource) *Result {
	if block.IsNil() {
		return r
	}
	r.blocks = append(r.blocks, block)
	return r
}

func (r *Result) WithDescription(description string, parts ...interface{}) *Result {
	if len(parts) == 0 {
		r.Description = description
	} else {
		r.Description = fmt.Sprintf(description, parts...)
	}

	return r
}

func (r *Result) WithSeverity(sev severity.Severity) *Result {
	r.Severity = sev
	return r
}

func (r *Result) WithStatus(status Status) *Result {
	r.Status = status
	return r
}

func (r *Result) WithAttributeAnnotation(attrName string) *Result {
	r.Attribute = attrName
	return r
}
