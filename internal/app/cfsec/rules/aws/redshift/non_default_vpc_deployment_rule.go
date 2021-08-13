package redshift

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
		LegacyID:  "AWS087",
		Service:   "redshift",
		ShortCode: "non-default-vpc-deployment",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_redshift_cluster" "bad_example" {
	cluster_identifier = "tf-redshift-cluster"
	database_name      = "mydb"
	master_username    = "foo"
	master_password    = "Mustbe8characters"
	node_type          = "dc1.large"
	cluster_type       = "single-node"
}
`},
			GoodExample: []string{`
resource "aws_redshift_cluster" "good_example" {
	cluster_identifier = "tf-redshift-cluster"
	database_name      = "mydb"
	master_username    = "foo"
	master_password    = "Mustbe8characters"
	node_type          = "dc1.large"
	cluster_type       = "single-node"

	cluster_subnet_group_name = "redshift_subnet"
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_cluster#cluster_subnet_group_name",
				"https://docs.aws.amazon.com/redshift/latest/mgmt/managing-clusters-vpc.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_redshift_cluster"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
