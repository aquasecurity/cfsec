package rds

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rule"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/rds"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{

		BadExample: []string{
			`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of rds sgr
Resources:
  Cluster:
    Type: AWS::RDS::DBCluster
    Properties:
      StorageEncrypted: false

`,
		},

		GoodExample: []string{
			`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of rds sgr
Resources:
  Cluster:
    Type: AWS::RDS::DBCluster
    Properties:
      StorageEncrypted: true
      KmsKeyId: "something"

`,
		},
		Base: rds.CheckEncryptClusterStorageData,
	})
}
