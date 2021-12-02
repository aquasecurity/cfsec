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
Description: Bad Example of SAM Table
Resources:
  BadFunction:
    Type: AWS::Serverless::SimpleTable
    Properties:
      TableName: Bad Table
      SSESpecification:
        SSEEnabled: false
`, `---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad Example of SAM Table
Resources:
  BadFunction:
    Type: AWS::Serverless::SimpleTable
    Properties:
      TableName: Bad Table
`,
		},

		GoodExample: []string{
			`---
AWSTemplateFormatVersion: 2010-09-09
Description: Good Example of SAM Table
Resources:
  GoodFunction:
    Type: AWS::Serverless::SimpleTable
    Properties:
      TableName: GoodTable
      SSESpecification:
        SSEEnabled: true
`,
		},

		Base: sam.CheckEnableTableEncryption,
	})
}
