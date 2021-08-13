package s3

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
		LegacyID:  "AWS002",
		Service:   "s3",
		ShortCode: "enable-bucket-logging",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_s3_bucket" "bad_example" {

}
`},
			GoodExample: []string{`
resource "aws_s3_bucket" "good_example" {
	logging {
		target_bucket = "target-bucket"
	}
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket",
				"https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_s3_bucket"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
