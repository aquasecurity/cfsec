package elasticsearch

// generator-locked
import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/resource"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/result"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/severity"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/rule"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS032",
		Service:   "elastic-search",
		ShortCode: "enable-in-transit-encryption",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_elasticsearch_domain" "bad_example" {
  domain_name = "domain-foo"

  node_to_node_encryption {
    enabled = false
  }
}
`},
			GoodExample: []string{`
resource "aws_elasticsearch_domain" "good_example" {
  domain_name = "domain-foo"

  node_to_node_encryption {
    enabled = true
  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#encrypt_at_rest",
				"https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/ntn.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_elasticsearch_domain"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
