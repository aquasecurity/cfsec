package vpc

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
		LegacyID:  "AWS018",
		Service:   "vpc",
		ShortCode: "add-decription-to-security-group",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_security_group" "bad_example" {
  name        = "http"

  ingress {
    description = "HTTP from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }
}
`},
			GoodExample: []string{`
resource "aws_security_group" "good_example" {
  name        = "http"
  description = "Allow inbound HTTP traffic"

  ingress {
    description = "HTTP from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule",
				"https://www.cloudconformity.com/knowledge-base/aws/EC2/security-group-rules-description.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_security_group", "aws_security_group_rule"},
		DefaultSeverity: severity.Low,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
