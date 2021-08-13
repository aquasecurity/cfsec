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
		LegacyID:  "AWS014",
		Service:   "autoscaling",
		ShortCode: "enable-at-rest-encryption",
		Documentation: rule.RuleDocumentation{
			BadExample: []string{`
resource "aws_launch_configuration" "bad_example" {
	root_block_device {
		encrypted = false
	}
}
`},
			GoodExample: []string{`
resource "aws_launch_configuration" "good_example" {
	root_block_device {
		encrypted = true
	}
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#ebs-ephemeral-and-root-block-devices",
				"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/RootDeviceStorage.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_launch_configuration"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
