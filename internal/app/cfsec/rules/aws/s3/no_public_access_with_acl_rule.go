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
		LegacyID:  "AWS001",
		Service:   "s3",
		ShortCode: "no-public-access-with-acl",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_s3_bucket" "bad_example" {
	acl = "public-read"
}
`},
			GoodExample: []string{`
resource "aws_s3_bucket" "good_example" {
	acl = "private"
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket",
				"https://aws.amazon.com/premiumsupport/knowledge-center/secure-s3-resources/",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_s3_bucket"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
