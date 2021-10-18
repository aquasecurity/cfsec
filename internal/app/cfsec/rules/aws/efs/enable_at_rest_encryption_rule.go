package efs

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/efs"
)

func init() {

	scanner.RegisterCheckRule(rules.Rule{

		BadExample: []string{`---
AWSTemplateFormatVersion: 2010-09-09
Resources:
  BadExample:
    Type: AWS::EFS::FileSystem
    Properties:
      BackupPolicy:
        Status: ENABLED
      LifecyclePolicies:
        - TransitionToIA: AFTER_60_DAYS
      PerformanceMode: generalPurpose
      Encrypted: false
      ThroughputMode: bursting
`},
		GoodExample: []string{`---
AWSTemplateFormatVersion: 2010-09-09
Resources:
  GoodExample:
    Type: AWS::EFS::FileSystem
    Properties:
      BackupPolicy:
        Status: ENABLED
      LifecyclePolicies:
        - TransitionToIA: AFTER_60_DAYS
      PerformanceMode: generalPurpose
      Encrypted: true
      ThroughputMode: bursting
`},
		Base: efs.CheckEnableAtRestEncryption,
	})
}
