package elasticache

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
		LegacyID:  "AWS036",
		Service:   "elasticache",
		ShortCode: "enable-in-transit-encryption",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_elasticache_replication_group" "bad_example" {
        replication_group_id = "foo"
        replication_group_description = "my foo cluster"

        transit_encryption_enabled = false
}
`},
			GoodExample: []string{`
resource "aws_elasticache_replication_group" "good_example" {
        replication_group_id = "foo"
        replication_group_description = "my foo cluster"

        transit_encryption_enabled = true
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_replication_group#transit_encryption_enabled",
				"https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/in-transit-encryption.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_elasticache_replication_group"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
