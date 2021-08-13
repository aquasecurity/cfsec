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
		LegacyID:  "AWS066",
		Service:   "eks",
		ShortCode: "encrypt-secrets",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_eks_cluster" "bad_example" {
    name = "bad_example_cluster"

    role_arn = var.cluster_arn
    vpc_config {
        endpoint_public_access = false
    }
}
`},
			GoodExample: []string{`
resource "aws_eks_cluster" "good_example" {
    encryption_config {
        resources = [ "secrets" ]
        provider {
            key_arn = var.kms_arn
        }
    }

    name = "good_example_cluster"
    role_arn = var.cluster_arn
    vpc_config {
        endpoint_public_access = false
    }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#encryption_config",
				"https://aws.amazon.com/about-aws/whats-new/2020/03/amazon-eks-adds-envelope-encryption-for-secrets-with-aws-kms/",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_eks_cluster"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
