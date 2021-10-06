package elb

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rule"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/elb"
)

func init() {

	scanner.RegisterCheckRule(rule.Rule{
		BadExample: []string{`---
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
