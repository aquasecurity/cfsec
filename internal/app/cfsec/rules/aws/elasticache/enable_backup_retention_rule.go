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
		LegacyID:  "AWS088",
		Service:   "elasticache",
		ShortCode: "enable-backup-retention",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_elasticache_cluster" "bad_example" {
	cluster_id           = "cluster-example"
	engine               = "redis"
	node_type            = "cache.m4.large"
	num_cache_nodes      = 1
	parameter_group_name = "default.redis3.2"
	engine_version       = "3.2.10"
	port                 = 6379
}
`},
			GoodExample: []string{`
resource "aws_elasticache_cluster" "good_example" {
	cluster_id           = "cluster-example"
	engine               = "redis"
	node_type            = "cache.m4.large"
	num_cache_nodes      = 1
	parameter_group_name = "default.redis3.2"
	engine_version       = "3.2.10"
	port                 = 6379

	snapshot_retention_limit = 5
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_cluster#snapshot_retention_limit",
				"https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/backups-automatic.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_elasticache_cluster"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
