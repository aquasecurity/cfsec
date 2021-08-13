package vpc

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
		LegacyID:  "AWS007",
		Service:   "vpc",
		ShortCode: "no-public-egress-sgr",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_security_group_rule" "bad_example" {
	type = "egress"
	cidr_blocks = ["0.0.0.0/0"]
}
`},
			GoodExample: []string{`
resource "aws_security_group_rule" "good_example" {
	type = "egress"
	cidr_blocks = ["10.0.0.0/16"]
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_security_group_rule"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
