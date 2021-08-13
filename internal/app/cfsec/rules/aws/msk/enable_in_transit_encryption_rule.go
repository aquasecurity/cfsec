package msk

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
		LegacyID:  "AWS022",
		Service:   "msk",
		ShortCode: "enable-in-transit-encryption",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_msk_cluster" "bad_example" {
	encryption_info {
		encryption_in_transit {
			client_broker = "TLS_PLAINTEXT"
			in_cluster = true
		}
	}
}
`},
			GoodExample: []string{`
resource "aws_msk_cluster" "good_example" {
	encryption_info {
		encryption_in_transit {
			client_broker = "TLS"
			in_cluster = true
		}
	}
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/msk_cluster#encryption_info-argument-reference",
				"https://docs.aws.amazon.com/msk/latest/developerguide/msk-encryption.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_msk_cluster"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
