package elasticsearch

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
		LegacyID:  "AWS070",
		Service:   "elastic-search",
		ShortCode: "enable-logging",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_elasticsearch_domain" "example" {
  // other config

  // One of the log_publishing_options has to be AUDIT_LOGS
  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
    log_type                 = "INDEX_SLOW_LOGS"
  }
}
`},
			GoodExample: []string{`
resource "aws_elasticsearch_domain" "example" {
  // other config

  // At minimum we should have AUDIT_LOGS enabled
  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
    log_type                 = "AUDIT_LOGS"
  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#log_publishing_options",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_elasticsearch_domain"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
