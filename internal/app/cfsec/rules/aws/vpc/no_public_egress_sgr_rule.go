package vpc

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rule"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/vpc"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{

		BadExample: []string{
			`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of egress rule
Resources:
  BadSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Limits security group egress traffic
      SecurityGroupEgress:
      - CidrIp: 80.1.2.3/32
        IpProtocol: "6"
`,
		},

		GoodExample: []string{
			`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of egress rule
Resources:
  BadSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Limits security group egress traffic
      SecurityGroupEgress:
      - CidrIp: 127.0.0.1/32
        IpProtocol: "6"
`,
		},
		Base: vpc.CheckNoPublicEgressSgr,
	})
}
