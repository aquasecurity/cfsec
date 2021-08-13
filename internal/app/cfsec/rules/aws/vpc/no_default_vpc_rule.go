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
		LegacyID:  "AWS082",
		Service:   "vpc",
		ShortCode: "no-default-vpc",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_default_vpc" "default" {
	tags = {
	  Name = "Default VPC"
	}
  }
`},
			GoodExample: []string{`
# no aws default vpc present
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/default_vpc",
				"https://docs.aws.amazon.com/vpc/latest/userguide/default-vpc.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_default_vpc"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
