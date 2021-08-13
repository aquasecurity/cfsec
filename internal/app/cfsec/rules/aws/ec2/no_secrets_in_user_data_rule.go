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
		LegacyID:  "AWS062",
		Service:   "ec2",
		ShortCode: "no-secrets-in-user-data",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_instance" "bad_example" {

  ami           = "ami-12345667"
  instance_type = "t2.small"

  user_data = <<EOF
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_DEFAULT_REGION=us-west-2 
EOF
}
`},
			GoodExample: []string{`
resource "aws_iam_instance_profile" "good_example" {
    // ...
}

resource "aws_instance" "good_example" {
  ami           = "ami-12345667"
  instance_type = "t2.small"

  iam_instance_profile = aws_iam_instance_profile.good_profile.arn

  user_data = <<EOF
  export GREETING=hello
EOF
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#user_data",
				"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-add-user-data.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_instance"},
		DefaultSeverity: severity.Critical,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
