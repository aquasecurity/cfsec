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
		LegacyID:  "AWS053",
		Service:   "rds",
		ShortCode: "enable-performance-insights",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_rds_cluster_instance" "bad_example" {
  name                 = "bar"
  performance_insights_enabled = true
  performance_insights_kms_key_id = ""
}
`},
			GoodExample: []string{`
resource "aws_rds_cluster_instance" "good_example" {
  name                 = "bar"
  performance_insights_enabled = true
  performance_insights_kms_key_id = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster_instance#performance_insights_kms_key_id",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance#performance_insights_kms_key_id",
				"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.htm",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_rds_cluster_instance", "aws_db_instance"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
