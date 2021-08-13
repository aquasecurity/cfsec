package eks

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
		LegacyID:  "AWS068",
		Service:   "eks",
		ShortCode: "no-public-cluster-access-to-cidr",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_eks_cluster" "bad_example" {
    // other config 

    name = "bad_example_cluster"
    role_arn = var.cluster_arn
    vpc_config {
        endpoint_public_access = true
    }
}
`},
			GoodExample: []string{`
resource "aws_eks_cluster" "good_example" {
    // other config 

    name = "good_example_cluster"
    role_arn = var.cluster_arn
    vpc_config {
        endpoint_public_access = true
        public_access_cidrs = ["10.2.0.0/8"]
    }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#vpc_config",
				"https://docs.aws.amazon.com/eks/latest/userguide/create-public-private-vpc.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_eks_cluster"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
