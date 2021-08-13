package vpc

// generator-locked
import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/result"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/severity"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/resource"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/rule"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
)

var outdatedSSLPolicies = []string{
	"ELBSecurityPolicy-2015-05",
	"ELBSecurityPolicy-TLS-1-0-2015-04",
	"ELBSecurityPolicy-2016-08",
	"ELBSecurityPolicy-TLS-1-1-2017-01",
}

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS010",
		Service:   "vpc",
		ShortCode: "use-secure-tls-policy",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_alb_listener" "bad_example" {
	ssl_policy = "ELBSecurityPolicy-TLS-1-1-2017-01"
	protocol = "HTTPS"
}
`},
			GoodExample: []string{`
resource "aws_alb_listener" "good_example" {
	ssl_policy = "ELBSecurityPolicy-TLS-1-2-2017-01"
	protocol = "HTTPS"
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_lb_listener", "aws_alb_listener"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
