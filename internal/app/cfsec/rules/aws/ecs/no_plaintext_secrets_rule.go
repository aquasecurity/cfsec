package ecs

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
		LegacyID:  "AWS013",
		Service:   "ecs",
		ShortCode: "no-plaintext-secrets",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_ecs_task_definition" "bad_example" {
  container_definitions = <<EOF
[
  {
    "name": "my_service",
    "essential": true,
    "memory": 256,
    "environment": [
      { "name": "ENVIRONMENT", "value": "development" },
      { "name": "DATABASE_PASSWORD", "value": "oh no D:"}
    ]
  }
]
EOF

}
`},
			GoodExample: []string{`
resource "aws_ecs_task_definition" "good_example" {
  container_definitions = <<EOF
[
  {
    "name": "my_service",
    "essential": true,
    "memory": 256,
    "environment": [
      { "name": "ENVIRONMENT", "value": "development" }
    ]
  }
]
EOF

}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition",
				"https://docs.aws.amazon.com/systems-manager/latest/userguide/integration-ps-secretsmanager.html",
				"https://www.vaultproject.io/",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_ecs_task_definition"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
