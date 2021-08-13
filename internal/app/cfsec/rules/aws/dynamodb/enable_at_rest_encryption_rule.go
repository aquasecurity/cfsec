package dynamodb

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
		LegacyID:  "AWS081",
		Service:   "dynamodb",
		ShortCode: "enable-at-rest-encryption",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_dax_cluster" "bad_example" {
	// no server side encryption at all
}

resource "aws_dax_cluster" "bad_example" {
	// other DAX config

	server_side_encryption {
		// empty server side encryption config
	}
}

resource "aws_dax_cluster" "bad_example" {
	// other DAX config

	server_side_encryption {
		enabled = false // disabled server side encryption
	}
}
`},
			GoodExample: []string{`
resource "aws_dax_cluster" "good_example" {
	// other DAX config

	server_side_encryption {
		enabled = true // enabled server side encryption
	}
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dax_cluster#server_side_encryption",
				"https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DAXEncryptionAtRest.html",
				"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dax-cluster.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_dax_cluster"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
