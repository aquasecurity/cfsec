package s3

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rule"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/s3"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{

		BadExample: []string{
			`---
Resources:
  BadExample:
    Properties:
      AccessControl: AuthenticatedRead
    Type: AWS::S3::Bucket
`,
		},

		GoodExample: []string{
			`---
Resources:
  GoodExample:
    Properties:
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
    Type: AWS::S3::Bucket
`,
		},

		Base: s3.CheckPublicACLsAreBlocked,
	})
}
