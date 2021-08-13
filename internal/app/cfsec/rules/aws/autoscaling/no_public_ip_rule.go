package autoscaling

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
		LegacyID:  "AWS012",
		Service:   "autoscaling",
		ShortCode: "no-public-ip",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_launch_configuration" "bad_example" {
	associate_public_ip_address = true
}
`},
			GoodExample: []string{`
resource "aws_launch_configuration" "good_example" {
	associate_public_ip_address = false
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/launch_configuration#associate_public_ip_address",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#associate_public_ip_address",
				"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_launch_configuration", "aws_instance"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
