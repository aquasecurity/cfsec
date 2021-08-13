package cloudwatch

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
		LegacyID:  "AWS089",
		Service:   "cloudwatch",
		ShortCode: "log-group-customer-key",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_cloudwatch_log_group" "bad_example" {
	name = "bad_example"

}
`},
			GoodExample: []string{`
resource "aws_cloudwatch_log_group" "good_example" {
	name = "good_example"

	kms_key_id = aws_kms_key.log_key.arn
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group#kms_key_id",
				"https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_cloudwatch_log_group"},
		DefaultSeverity: severity.Low,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
