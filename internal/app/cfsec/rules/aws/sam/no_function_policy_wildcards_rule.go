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
Description: Bad Example of SAM Function
Resources:
  BadFunction:
    Type: AWS::Serverless::Function
    Properties:
      PackageType: Image
      ImageUri: account-id.dkr.ecr.region.amazonaws.com/ecr-repo-name:image-name
      ImageConfig:
        Command:
          - "app.lambda_handler"
        EntryPoint:
          - "entrypoint1"
        WorkingDirectory: "workDir"
      Policies:  
        - AWSLambdaExecute
        - Version: '2012-10-17'
          Statement:
          - Effect: Allow
            Action:
            - s3:*
            Resource: 'arn:aws:s3:::my-bucket/*'
`,
		},

		GoodExample: []string{
			`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good Example of SAM Function
Resources:
  GoodFunction:
    Type: AWS::Serverless::Function
    Properties:
      PackageType: Image
      ImageUri: account-id.dkr.ecr.region.amazonaws.com/ecr-repo-name:image-name
      ImageConfig:
        Command:
          - "app.lambda_handler"
        EntryPoint:
          - "entrypoint1"
        WorkingDirectory: "workDir"
      Policies:  
        - AWSLambdaExecute
        - Version: '2012-10-17'
          Statement:
          - Effect: Allow
            Action:
            - s3:GetObject
            - s3:GetObjectACL
            Resource: 'arn:aws:s3:::my-bucket/*'
`,
		},

		Base: sam.CheckNoFunctionPolicyWildcards,
	})
}
