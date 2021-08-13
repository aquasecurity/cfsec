package efs

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
		LegacyID:  "AWS048",
		Service:   "efs",
		ShortCode: "enable-at-rest-encryption",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_efs_file_system" "bad_example" {
  name       = "bar"
  encrypted  = false
  kms_key_id = ""
}`},
			GoodExample: []string{`
resource "aws_efs_file_system" "good_example" {
  name       = "bar"
  encrypted  = true
  kms_key_id = "my_kms_key"
}`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/efs_file_system",
				"https://docs.aws.amazon.com/efs/latest/ug/encryption.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_efs_file_system"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
