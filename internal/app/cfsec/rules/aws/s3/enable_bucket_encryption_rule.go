package s3

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/resource"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/result"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rule"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/severity"
	"github.com/awslabs/goformation/v5/cloudformation/s3"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS017",
		Service:   "s3",
		ShortCode: "enable-bucket-encryption",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
Parameters:
  BucketName: 
    Type: String
    Default: naughty

Resources:
  S3Bucket:
    Type: 'AWS::S3::Bucket'
    DeletionPolicy: Retain
    Properties:
      BucketName: 
        Ref: BucketName
      BucketEncryption:
        ServerSideEncryptionConfiguration:
        - BucketKeyEnabled: false
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
				"https://tfsec.dev/docs/aws/s3/enable-bucket-encryption/#aws/s3",
				"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-bucketencryption.html",
				"https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html",
			},
		},
		RequiredTypes:   []string{"AWS::S3::Bucket"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, r resource.Resource) {

			bucket := r.Underlying().(*s3.Bucket)

			if bucket.BucketEncryption == nil {
				set.AddResult().
					WithDescription("Resource '%s' does not have encryption set", r.Name())
				return
			}

			if bucket.BucketEncryption.ServerSideEncryptionConfiguration == nil {
				set.AddResult().
					WithDescription("Resource '%s' does not have any server side encryption set", r.Name())
				return
			}

			for _, sse := range bucket.BucketEncryption.ServerSideEncryptionConfiguration {

				if !sse.BucketKeyEnabled {
					set.AddResult().
						WithDescription("Resource '%s' has BucketKeyEnabled set to false", r.Name()).
						WithAttributeAnnotation("BucketKeyEnabled:")
				}
			}

		},
	})
}
