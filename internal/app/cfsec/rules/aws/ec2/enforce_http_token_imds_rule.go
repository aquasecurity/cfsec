package ec2

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
		LegacyID:  "AWS079",
		Service:   "ec2",
		ShortCode: "enforce-http-token-imds",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_instance" "bad_example" {
  ami           = "ami-005e54dee72cc1d00"
  instance_type = "t2.micro"
}
`},
			GoodExample: []string{`
resource "aws_instance" "good_example" {
  ami           = "ami-005e54dee72cc1d00"
  instance_type = "t2.micro"
  metadata_options {
	http_tokens = "required"
  }	
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#metadata-options",
				"https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_instance"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
