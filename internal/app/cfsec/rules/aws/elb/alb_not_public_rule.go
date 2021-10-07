package elb

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/elb"
)

func init() {

	scanner.RegisterCheckRule(rules.Rule{
		BadExample: []string{`---
Resources:
  BadExample:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      LoadBalancerAttributes: 
        - Key: something
          Value: somevalue
      Name: BadExample
      Type: application
`},
		GoodExample: []string{`---
Resources:
  GoodExample:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      LoadBalancerAttributes: 
        - Key: something
          Value: somevalue
      Name: BadExample
      Type: application
      Scheme: internal
`},
		Base: elb.CheckAlbNotPublic,
	})
}
