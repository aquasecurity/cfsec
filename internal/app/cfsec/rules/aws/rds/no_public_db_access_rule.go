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
		LegacyID:  "AWS011",
		Service:   "rds",
		ShortCode: "no-public-db-access",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_db_instance" "bad_example" {
	publicly_accessible = true
}
`},
			GoodExample: []string{`
resource "aws_db_instance" "good_example" {
	publicly_accessible = false
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_db_instance", "aws_dms_replication_instance", "aws_rds_cluster_instance", "aws_redshift_cluster"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
