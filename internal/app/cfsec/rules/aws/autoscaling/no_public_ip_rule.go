package autoscaling

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rule"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/autoscaling"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{

		BadExample: []string{
			`---
Resources:
  BadExample:
    Properties:
      AssociatePublicIpAddress: true
      ImageId: ami-123456
      InstanceType: t2.small
    Type: AWS::AutoScaling::LaunchConfiguration
`,
		},

		GoodExample: []string{
			`---
Resources:
  GoodExample:
    Properties:
      ImageId: ami-123456
      InstanceType: t2.small
    Type: AWS::AutoScaling::LaunchConfiguration
`,
		},

		Base: autoscaling.CheckNoPublicIp,
	})
}
