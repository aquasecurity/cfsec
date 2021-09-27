package config

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rule"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/config"
)

func init() {

	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`---
Resources:
  BadExample:
    Type: AWS::Config::ConfigurationAggregator
    Properties:
      ConfigurationAggregatorName: "BadAccountLevelAggregation"
`},
		GoodExample: []string{`---
Resources:
  GoodExample:
    Type: AWS::Config::ConfigurationAggregator
    Properties:
      AccountAggregationSources:
        - AllAwsRegions: true
      ConfigurationAggregatorName: "GoodAccountLevelAggregation"
`,
`---
Resources:
  GoodExample:
    Type: AWS::Config::ConfigurationAggregator
    Properties:
      OrganizationAggregationSource: 
        AllAwsRegions: true
      ConfigurationAggregatorName: "GoodAccountLevelAggregation"
`},
		Base: config.CheckAggregateAllRegions,
	})

}