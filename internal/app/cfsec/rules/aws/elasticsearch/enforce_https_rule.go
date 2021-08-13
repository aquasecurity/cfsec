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
		LegacyID:  "AWS033",
		Service:   "elastic-search",
		ShortCode: "enforce-https",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_elasticsearch_domain" "bad_example" {
  domain_name = "domain-foo"

  domain_endpoint_options {
    enforce_https = false
  }
}
`},
			GoodExample: []string{`
resource "aws_elasticsearch_domain" "good_example" {
  domain_name = "domain-foo"

  domain_endpoint_options {
    enforce_https = true
  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#enforce_https",
				"https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-data-protection.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_elasticsearch_domain"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
