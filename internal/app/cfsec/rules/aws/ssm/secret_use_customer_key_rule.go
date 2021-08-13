package ssm

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
		LegacyID:  "AWS095",
		Service:   "ssm",
		ShortCode: "secret-use-customer-key",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_secretsmanager_secret" "bad_example" {
  name       = "lambda_password"
}
`},
			GoodExample: []string{`
resource "aws_kms_key" "secrets" {
	enable_key_rotation = true
}

resource "aws_secretsmanager_secret" "good_example" {
  name       = "lambda_password"
  kms_key_id = aws_kms_key.secrets.arn
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret#kms_key_id",
				"https://docs.aws.amazon.com/kms/latest/developerguide/services-secrets-manager.html#asm-encrypt",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_secretsmanager_secret"},
		DefaultSeverity: severity.Low,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
