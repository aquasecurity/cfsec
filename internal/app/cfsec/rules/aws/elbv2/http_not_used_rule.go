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
		LegacyID:  "AWS004",
		Service:   "elbv2",
		ShortCode: "http-not-used",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_alb_listener" "bad_example" {
	protocol = "HTTP"
}
`},
			GoodExample: []string{`
resource "aws_alb_listener" "good_example" {
	protocol = "HTTPS"
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener",
				"https://www.cloudflare.com/en-gb/learning/ssl/why-is-http-not-secure/",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_lb_listener", "aws_alb_listener"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, r resource.Resource) {
			// didn't find the referenced block, log and move on

		},
	})
}
