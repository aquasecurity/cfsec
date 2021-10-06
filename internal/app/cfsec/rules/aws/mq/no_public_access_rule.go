package rds

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rule"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/mq"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{

		BadExample: []string{
			`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example
Resources:
  Broker:
    Type: AWS::AmazonMQ::Broker
    Properties:
      PubliclyAccessible: true

`,
		},

		GoodExample: []string{
			`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example
Resources:
  Broker:
    Type: AWS::AmazonMQ::Broker
    Properties:
      PubliclyAccessible: false

`,
		},
		Base: mq.CheckNoPublicAccess,
	})
}
