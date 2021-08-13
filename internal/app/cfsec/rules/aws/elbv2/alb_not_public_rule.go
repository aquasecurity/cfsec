package elbv2

// generator-locked
import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/result"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/severity"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/resource"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/rule"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS005",
		Service:   "elbv2",
		ShortCode: "alb-not-public",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_alb" "bad_example" {
	internal = false
}
`},
			GoodExample: []string{`
resource "aws_alb" "good_example" {
	internal = true
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_alb", "aws_elb", "aws_lb"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
