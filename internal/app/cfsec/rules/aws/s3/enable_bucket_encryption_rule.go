package s3

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/resource"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/result"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rule"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/awslabs/goformation/v5/cloudformation/s3"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS017",
		Service:   "s3",
		ShortCode: "enable-bucket-encryption",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_s3_bucket" "bad_example" {
  bucket = "mybucket"
}
`},
			GoodExample: []string{`
resource "aws_s3_bucket" "good_example" {
  bucket = "mybucket"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = "arn"
        sse_algorithm     = "aws:kms"
      }
    }
  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket#enable-default-server-side-encryption",
				"https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html",
			},
		},
		RequiredTypes: []string{"AWS::S3::Bucket"},
		CheckFunc: func(set result.Set, r resource.Resource) {

			bucket := r.Underlying().(*s3.Bucket)

			if bucket.BucketEncryption == nil {
				set.AddResult().
					WithDescription("Resource '%s' does not have encryption set", r.Name())
			}

		},
	})
}
