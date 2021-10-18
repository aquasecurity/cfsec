package config

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/config"
)

func init() {

	scanner.RegisterCheckRule(rules.Rule{
		BadExample: []string{`---
AWSTemplateFormatVersion: 2010-09-09
Resources:
  BadExample:
    Type: AWS::Config::ConfigurationAggregator
    Properties:
      ConfigurationAggregatorName: "BadAccountLevelAggregation"
`},
		GoodExample: []string{`---
AWSTemplateFormatVersion: 2010-09-09
Resources:
  GoodExample:
    Type: AWS::Config::ConfigurationAggregator
    Properties:
      AccountAggregationSources:
        - AllAwsRegions: true
      ConfigurationAggregatorName: "GoodAccountLevelAggregation"
`,
			`---
AWSTemplateFormatVersion: 2010-09-09
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
