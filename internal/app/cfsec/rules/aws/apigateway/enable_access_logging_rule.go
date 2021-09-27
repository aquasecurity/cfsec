package apigateway

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rule"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/apigateway"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{

		BadExample: []string{
			`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad Example of ApiGateway
Resources:
  BadApi:
    Type: AWS::ApiGatewayV2::Api
  BadApiStage:
    Type: AWS::ApiGatewayV2::Stage
    Properties:
      AccessLogSettings:
        Format: json
      ApiId: BadApi
      StageName: BadApiStage
`,
		},

		GoodExample: []string{
			`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good Example of ApiGateway
Resources:
  GoodApi:
    Type: AWS::ApiGatewayV2::Api
  GoodApiStage:
    Type: AWS::ApiGatewayV2::Stage
    Properties:
      AccessLogSettings:
        DestinationArn: gateway-logging
        Format: json
      ApiId: GoodApi
      StageName: GoodApiStage
`,
		},

		Base: apigateway.CheckEnableAccessLogging,
	})
}
