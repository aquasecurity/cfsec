package ecr

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
		LegacyID:  "AWS093",
		Service:   "ecr",
		ShortCode: "repository-customer-key",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_ecr_repository" "bad_example" {
	name                 = "bar"
	image_tag_mutability = "MUTABLE"
  
	image_scanning_configuration {
	  scan_on_push = true
	}
  }
`},
			GoodExample: []string{`
resource "aws_kms_key" "ecr_kms" {
	enable_key_rotation = true
}

resource "aws_ecr_repository" "good_example" {
	name                 = "bar"
	image_tag_mutability = "MUTABLE"
  
	image_scanning_configuration {
	  scan_on_push = true
	}

	encryption_configuration {
		encryption_type = "KMS"
		kms_key = aws_kms_key.ecr_kms.key_id
	}
  }
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository#encryption_configuration",
				"https://docs.aws.amazon.com/AmazonECR/latest/userguide/encryption-at-rest.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_ecr_repository"},
		DefaultSeverity: severity.Low,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
