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
		LegacyID:  "AWS078",
		Service:   "ecr",
		ShortCode: "enforce-immutable-repository",
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
resource "aws_ecr_repository" "good_example" {
  name                 = "bar"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository",
				"https://sysdig.com/blog/toctou-tag-mutability/",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_ecr_repository"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
