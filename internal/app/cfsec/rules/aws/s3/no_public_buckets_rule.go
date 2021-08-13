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
		LegacyID:  "AWS075",
		Service:   "s3",
		ShortCode: "no-public-buckets",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_s3_bucket_public_access_block" "bad_example" {
	bucket = aws_s3_bucket.example.id
}

resource "aws_s3_bucket_public_access_block" "bad_example" {
	bucket = aws_s3_bucket.example.id
  
	restrict_public_buckets = false
}
`},
			GoodExample: []string{`
resource "aws_s3_bucket_public_access_block" "good_example" {
	bucket = aws_s3_bucket.example.id
  
	restrict_public_buckets = true
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#restrict_public_buckets¡",
				"https://docs.aws.amazon.com/AmazonS3/latest/dev-retired/access-control-block-public-access.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_s3_bucket_public_access_block"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
