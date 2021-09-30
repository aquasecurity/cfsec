package ecs

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rule"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/ecs"
)

func init() {

	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`---
Resources:
  BadExample:
    Type: 'AWS::ECS::Cluster'
    Properties:
      ClusterName: MyCluster
`},
		GoodExample: []string{`---
Resources:
  GoodExample:
    Type: 'AWS::ECS::Cluster'
    Properties:
      ClusterName: MyCluster
      ClusterSettings:
        - Name: containerInsights
          Value: enabled
`},
		Base: ecs.CheckEnableContainerInsight,
	})

}
