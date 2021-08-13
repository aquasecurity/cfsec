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
		LegacyID:  "AWS086",
		Service:   "dynamodb",
		ShortCode: "enable-recovery",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_dynamodb_table" "bad_example" {
	name             = "example"
	hash_key         = "TestTableHashKey"
	billing_mode     = "PAY_PER_REQUEST"
	stream_enabled   = true
	stream_view_type = "NEW_AND_OLD_IMAGES"
  
	attribute {
	  name = "TestTableHashKey"
	  type = "S"
	}
}
`},
			GoodExample: []string{`
resource "aws_dynamodb_table" "good_example" {
	name             = "example"
	hash_key         = "TestTableHashKey"
	billing_mode     = "PAY_PER_REQUEST"
	stream_enabled   = true
	stream_view_type = "NEW_AND_OLD_IMAGES"
  
	attribute {
	  name = "TestTableHashKey"
	  type = "S"
	}

	point_in_time_recovery {
		enabled = true
	}
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dynamodb_table#point_in_time_recovery",
				"https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_dynamodb_table"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
