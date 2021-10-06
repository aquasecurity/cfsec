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
  BadExampleListener:
    Type: AWS::ElasticLoadBalancingV2::Listener
    Properties:
      DefaultActions:
        - Type: "forward"
          RedirectConfig:
            Protocol: "HTTP"
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
		GoodExample: []string{`---
Resources:
  GoodExample:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      LoadBalancerAttributes:
        - Key: routing.http.drop_invalid_header_fields.enabled
          Value: false
      Name: BadExample
      Type: application
  GoodExampleListener:
    Type: AWS::ElasticLoadBalancingV2::Listener
    Properties:
      DefaultActions:
        - Type: "forward"
          RedirectConfig:
            Protocol: "HTTPS"
            Port: 443
            Host: "#{host}"
            Path: "/#{path}"
            Query: "#{query}"
            StatusCode: "HTTP_301"
      LoadBalancerArn: !Ref GoodExample
      Port: 80
      Protocol: "HTTPS"
      SslPolicy: ELBSecurityPolicy-FS-1-2-Res-2020-10
`},
		Base: elb.CheckHttpNotUsed,
	})
}
