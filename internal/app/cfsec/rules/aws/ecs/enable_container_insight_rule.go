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
		LegacyID:  "AWS090",
		Service:   "ecs",
		ShortCode: "enable-container-insight",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_ecs_cluster" "bad_example" {
  	name = "services-cluster"
}
`},
			GoodExample: []string{`
resource "aws_ecs_cluster" "good_example" {
	name = "services-cluster"
  
	setting {
	  name  = "containerInsights"
	  value = "enabled"
	}
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_cluster#setting",
				"https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/ContainerInsights.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_ecs_cluster"},
		DefaultSeverity: severity.Low,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
