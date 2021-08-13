package cloudfront

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
		LegacyID:  "AWS071",
		Service:   "cloudfront",
		ShortCode: "enable-logging",
		Documentation: rule.RuleDocumentation{
			BadExample: []string{`
resource "aws_cloudfront_distribution" "bad_example" {
	// other config
	// no logging_config
}
`},
			GoodExample: []string{`
resource "aws_cloudfront_distribution" "good_example" {
	// other config
	logging_config {
		include_cookies = false
		bucket          = "mylogs.s3.amazonaws.com"
		prefix          = "myprefix"
	}
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution#logging_config",
				"https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_cloudfront_distribution"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
