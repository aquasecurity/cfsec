package rds

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
		LegacyID:  "AWS052",
		Service:   "rds",
		ShortCode: "encrypt-instance-storage-data",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_db_instance" "bad_example" {
	
}
`},
			GoodExample: []string{`
resource "aws_db_instance" "good_example" {
	storage_encrypted  = true
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance",
				"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_db_instance"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
