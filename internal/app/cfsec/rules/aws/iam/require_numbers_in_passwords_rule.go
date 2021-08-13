package iam

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
		LegacyID:  "AWS041",
		Service:   "iam",
		ShortCode: "require-numbers-in-passwords",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_iam_account_password_policy" "bad_example" {
	# ...
	# require_numbers not set
	# ...
}
`},
			GoodExample: []string{`
resource "aws_iam_account_password_policy" "good_example" {
	# ...
	require_numbers = true
	# ...
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy",
				"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_iam_account_password_policy"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
