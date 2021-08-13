package athena

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
		LegacyID:  "AWS059",
		Service:   "athena",
		ShortCode: "enable-at-rest-encryption",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_athena_database" "bad_example" {
  name   = "database_name"
  bucket = aws_s3_bucket.hoge.bucket
}

resource "aws_athena_workgroup" "bad_example" {
  name = "example"

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true

    result_configuration {
      output_location = "s3://${aws_s3_bucket.example.bucket}/output/"
    }
  }
}
`},
			GoodExample: []string{`
resource "aws_athena_database" "good_example" {
  name   = "database_name"
  bucket = aws_s3_bucket.hoge.bucket

  encryption_configuration {
     encryption_option = "SSE_KMS"
     kms_key_arn       = aws_kms_key.example.arn
 }
}

resource "aws_athena_workgroup" "good_example" {
  name = "example"

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true

    result_configuration {
      output_location = "s3://${aws_s3_bucket.example.bucket}/output/"

      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = aws_kms_key.example.arn
      }
    }
  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/athena_workgroup#encryption_configuration",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/athena_database#encryption_configuration",
				"https://docs.aws.amazon.com/athena/latest/ug/encryption.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_athena_database", "aws_athena_workgroup"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
