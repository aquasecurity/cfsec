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
      BlockDeviceMappings:
        - DeviceName: root
          Ebs:
            Encrypted: true
        - DeviceName: data
          Ebs:
            Encrypted: false
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
      BlockDeviceMappings:
        - DeviceName: root
          Ebs:
            Encrypted: true
      ImageId: ami-123456
      InstanceType: t2.small
    Type: AWS::AutoScaling::LaunchConfiguration
`,
		},

		Base: autoscaling.CheckEnableAtRestEncryption,
	})
}
