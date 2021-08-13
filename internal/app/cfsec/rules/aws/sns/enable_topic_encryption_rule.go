package sns

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
		LegacyID:  "AWS016",
		Service:   "sns",
		ShortCode: "enable-topic-encryption",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_sns_topic" "bad_example" {
	# no key id specified
}
`},
			GoodExample: []string{`
resource "aws_sns_topic" "good_example" {
	kms_master_key_id = "/blah"
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic#example-with-server-side-encryption-sse",
				"https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_sns_topic"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
