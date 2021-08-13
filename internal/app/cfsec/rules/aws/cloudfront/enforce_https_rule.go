package cloudfront

// generator-locked
import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/resource"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/result"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/severity"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/rule"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS020",
		Service:   "cloudfront",
		ShortCode: "enforce-https",
		Documentation: rule.RuleDocumentation{
			BadExample: []string{`
resource "aws_cloudfront_distribution" "bad_example" {
	default_cache_behavior {
	    viewer_protocol_policy = "allow-all"
	  }
}
`},
			GoodExample: []string{`
resource "aws_cloudfront_distribution" "good_example" {
	default_cache_behavior {
	    viewer_protocol_policy = "redirect-to-https"
	  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution#viewer_protocol_policy",
				"https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-cloudfront-to-s3-origin.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_cloudfront_distribution"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
