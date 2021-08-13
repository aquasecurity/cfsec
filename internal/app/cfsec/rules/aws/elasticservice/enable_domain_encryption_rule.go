package elasticservice

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
		LegacyID:  "AWS031",
		Service:   "elastic-service",
		ShortCode: "enable-domain-encryption",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_elasticsearch_domain" "bad_example" {
  domain_name = "domain-foo"

  encrypt_at_rest {
    enabled = false
  }
}
`},
			GoodExample: []string{`
resource "aws_elasticsearch_domain" "good_example" {
  domain_name = "domain-foo"

  encrypt_at_rest {
    enabled = true
  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#encrypt_at_rest",
				"https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/encryption-at-rest.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_elasticsearch_domain"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
