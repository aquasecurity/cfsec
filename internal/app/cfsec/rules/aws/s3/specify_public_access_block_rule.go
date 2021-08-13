package s3

// generator-locked
import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/resource"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/result"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rule"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/severity"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS098",
		Service:   "s3",
		ShortCode: "specify-public-access-block",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_s3_bucket" "example" {
	bucket = "example"
	acl = "private-read"
}
`},
			GoodExample: []string{`
resource "aws_s3_bucket" "example" {
	bucket = "example"
	acl = "private-read"
}
  
resource "aws_s3_bucket_public_access_block" "example" {
	bucket = aws_s3_bucket.example.id
	block_public_acls   = true
	block_public_policy = true
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block#bucket",
				"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_s3_bucket"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
