package elb

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/elb"
)

func init() {

	scanner.RegisterCheckRule(rules.Rule{
		BadExample: []string{`---
AWSTemplateFormatVersion: 2010-09-09
Resources:
  BadExample:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      LoadBalancerAttributes: 
        - Key: routing.http.drop_invalid_header_fields.enabled
          Value: false
      Name: BadExample
      Type: application
`},
		GoodExample: []string{`---
AWSTemplateFormatVersion: 2010-09-09
Resources:
  GoodExample:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      LoadBalancerAttributes: 
        - Key: routing.http.drop_invalid_header_fields.enabled
          Value: true
      Name: BadExample
      Type: application
      Scheme: internal
`},
		Base: elb.CheckDropInvalidHeaders,
	})
}
