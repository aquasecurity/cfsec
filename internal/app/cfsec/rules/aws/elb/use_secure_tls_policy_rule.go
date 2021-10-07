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
      IpAddressType: "String"
      LoadBalancerAttributes: LoadBalancerAttributes
      Name: "String"
      Scheme: "String"
      SecurityGroups: SecurityGroups
      SubnetMappings: SubnetMappings
      Subnets: Subnets
      Tags: Tags
      Type: "String"
  BadExampleListener:
    Type: "AWS::ElasticLoadBalancingV2::Listener"
    Properties:
      DefaultActions:
        - Type: "redirect"
          RedirectConfig:
            Protocol: "HTTPS"
            Port: 443
            Host: "#{host}"
            Path: "/#{path}"
            Query: "#{query}"
            StatusCode: "HTTP_301"
      LoadBalancerArn: !Ref BadExample
      Port: 80
      Protocol: "HTTP"
`},
		GoodExample: []string{`---
Resources:
  BadExample:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      IpAddressType: "String"
      LoadBalancerAttributes: LoadBalancerAttributes
      Name: "String"
      Scheme: "String"
      SecurityGroups: SecurityGroups
      SubnetMappings: SubnetMappings
      Subnets: Subnets
      Tags: Tags
      Type: "String"
  BadExampleListener:
    Type: "AWS::ElasticLoadBalancingV2::Listener"
    Properties:
      DefaultActions:
        - Type: "redirect"
          RedirectConfig:
            Protocol: "HTTPS"
            Port: 443
            Host: "#{host}"
            Path: "/#{path}"
            Query: "#{query}"
            StatusCode: "HTTP_301"
      LoadBalancerArn: !Ref BadExample
      Port: 80
      Protocol: "HTTP"
      SslPolicy: ELBSecurityPolicy-FS-1-2-Res-2020-10

`},
		Base: elb.CheckUseSecureTlsPolicy,
	})
}
