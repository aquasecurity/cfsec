package apigateway

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
		LegacyID:  "AWS025",
		Service:   "api-gateway",
		ShortCode: "use-secure-tls-policy",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_api_gateway_domain_name" "bad_example" {
	security_policy = "TLS_1_0"
}
`},
			GoodExample: []string{`
resource "aws_api_gateway_domain_name" "good_example" {
	security_policy = "TLS_1_2"
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_domain_name#security_policy",
				"https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-custom-domain-tls-version.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_api_gateway_domain_name"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
