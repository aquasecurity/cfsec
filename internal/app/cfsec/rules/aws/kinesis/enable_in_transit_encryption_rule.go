package kinesis

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
		LegacyID:  "AWS024",
		Service:   "kinesis",
		ShortCode: "enable-in-transit-encryption",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_kinesis_stream" "bad_example" {
	encryption_type = "NONE"
}
`},
			GoodExample: []string{`
resource "aws_kinesis_stream" "good_example" {
	encryption_type = "KMS"
	kms_key_id = "my/special/key"
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kinesis_stream#encryption_type",
				"https://docs.aws.amazon.com/streams/latest/dev/server-side-encryption.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_kinesis_stream"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
