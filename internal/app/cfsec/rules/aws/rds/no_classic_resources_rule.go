package rds

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
		LegacyID:  "AWS003",
		Service:   "rds",
		ShortCode: "no-classic-resources",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_db_security_group" "bad_example" {
  # ...
}
`},
			GoodExample: []string{`
resource "aws_security_group" "good_example" {
  # ...
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_security_group",
				"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-classic-platform.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_db_security_group", "aws_redshift_security_group", "aws_elasticache_security_group"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
