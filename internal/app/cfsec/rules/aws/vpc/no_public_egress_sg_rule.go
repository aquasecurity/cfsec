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
		LegacyID:  "AWS009",
		Service:   "vpc",
		ShortCode: "no-public-egress-sg",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_security_group" "bad_example" {
	egress {
		cidr_blocks = ["0.0.0.0/0"]
	}
}
`},
			GoodExample: []string{`
resource "aws_security_group" "good_example" {
	egress {
		cidr_blocks = ["1.2.3.4/32"]
	}
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_security_group"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
