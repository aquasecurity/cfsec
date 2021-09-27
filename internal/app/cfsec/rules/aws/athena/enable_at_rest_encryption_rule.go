package athena

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rule"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/athena"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{

		BadExample: []string{
			`---
Resources:
  BadExample:
    Properties:
      Name: badExample
      WorkGroupConfiguration:
        ResultConfiguration:
    Type: AWS::Athena::WorkGroup
`,

		},

		GoodExample: []string{
			`---
Resources:
  GoodExample:
    Properties:
      Name: goodExample
      WorkGroupConfiguration:
        ResultConfiguration:
          EncryptionConfiguration:
            EncryptionOption: SSE_KMS
    Type: AWS::Athena::WorkGroup
`,
		},

		Base: athena.CheckEnableAtRestEncryption,
	})
}
