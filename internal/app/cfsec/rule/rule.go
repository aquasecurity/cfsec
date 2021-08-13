package rule

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/resource"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/result"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/severity"
)

// Rule is a targeted security test which can be applied to terraform templates. It includes the types to run on e.g.
// "resource", and the labels to run on e.g. "aws_s3_bucket".
type Rule struct {
	LegacyID string

	Service   string // EC2
	ShortCode string // ebs-volume-encrypted

	Documentation   RuleDocumentation
	RequiredTypes   []string
	RequiredLabels  []string
	RequiredSources []string
	DefaultSeverity severity.Severity
	CheckFunc       func(result.Set, resource.Resource)
}

func (r Rule) ID() string {
	return strings.ToLower(fmt.Sprintf("%s-%s", r.Service, r.ShortCode))
}

func (r Rule) MatchesID(id string) bool {
	return r.LegacyID == id || r.ID() == id
}

type RuleDocumentation struct {
	// BadExample (hcl) contains Terraform code which would cause the check to fail
	BadExample []string

	// GoodExample (hcl) modifies the BadExample content to cause the check to pass
	GoodExample []string

	// Links are URLs which contain further reading related to the check
	Links []string
}
