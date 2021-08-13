package sqs

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
		LegacyID:  "AWS047",
		Service:   "sqs",
		ShortCode: "no-wildcards-in-policy-documents",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_sqs_queue_policy" "bad_example" {
  queue_url = aws_sqs_queue.q.id

  policy = <<POLICY
{
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "*"
    }
  ]
}
POLICY
}
`},
			GoodExample: []string{`
resource "aws_sqs_queue_policy" "good_example" {
  queue_url = aws_sqs_queue.q.id

  policy = <<POLICY
{
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sqs:SendMessage"
    }
  ]
}
POLICY
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue_policy",
				"https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-security-best-practices.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_sqs_queue_policy"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
