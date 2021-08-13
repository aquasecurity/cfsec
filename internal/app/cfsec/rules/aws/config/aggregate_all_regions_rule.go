package config

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
		LegacyID:  "AWS085",
		Service:   "config",
		ShortCode: "aggregate-all-regions",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_config_configuration_aggregator" "bad_example" {
	name = "example"
	  
	account_aggregation_source {
	  account_ids = ["123456789012"]
	  regions     = ["us-west-2", "eu-west-1"]
	}
}
`},
			GoodExample: []string{`
resource "aws_config_configuration_aggregator" "good_example" {
	name = "example"
	  
	account_aggregation_source {
	  account_ids = ["123456789012"]
	  all_regions = true
	}
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/config_configuration_aggregator#all_regions",
				"https://docs.aws.amazon.com/config/latest/developerguide/aggregate-data.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_config_configuration_aggregator"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
