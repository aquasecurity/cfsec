package sam

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/sam"
)

func init() {
	scanner.RegisterCheckRule(rules.Rule{

		BadExample: []string{
			`---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad Example of SAM API
Resources:
  HttpApi:
    Type: AWS::Serverless::HttpApi
    Properties:
    Properties:
      Name: Good SAM API example
      StageName: Prod
      Tracing: Passthrough
`,
		},

		GoodExample: []string{
			`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good Example of SAM API
Resources:
  ApiGatewayApi:
    Type: AWS::Serverless::HttpApi
    Properties:
      Name: Good SAM API example
      StageName: Prod
      Tracing: Activey
      AccessLogSetting:
        DestinationArn: gateway-logging
        Format: json
`,
		},

		Base: sam.CheckEnableHttpApiAccessLogging,
	})
}
