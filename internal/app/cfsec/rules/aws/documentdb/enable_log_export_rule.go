package documentdb

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rule"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/documentdb"
)

func init() {

	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`---
Resources:
  BadExample:
    Type: "AWS::DocDB::DBCluster"
    Properties:
      BackupRetentionPeriod : 8
      DBClusterIdentifier : "sample-cluster"
      DBClusterParameterGroupName : "default.docdb3.6"
`},
		GoodExample: []string{`---
Resources:
  GoodExample:
    Type: "AWS::DocDB::DBCluster"
    Properties:
      BackupRetentionPeriod : 8
      DBClusterIdentifier : "sample-cluster"
      DBClusterParameterGroupName : "default.docdb3.6"
      EnableCloudwatchLogsExports:
	  - audit
      - profiler
`},
		Base: documentdb.CheckEnableLogExport,
	})
}