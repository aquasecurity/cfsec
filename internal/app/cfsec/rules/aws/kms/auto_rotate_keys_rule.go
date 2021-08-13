package kms

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
		LegacyID:  "AWS019",
		Service:   "kms",
		ShortCode: "auto-rotate-keys",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_kms_key" "bad_example" {
	enable_key_rotation = false
}
`},
			GoodExample: []string{`
resource "aws_kms_key" "good_example" {
	enable_key_rotation = true
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key#enable_key_rotation",
				"https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_kms_key"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
