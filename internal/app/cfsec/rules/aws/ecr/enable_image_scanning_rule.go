package ecr

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/ecr"
)

func init() {

	scanner.RegisterCheckRule(rules.Rule{

		BadExample: []string{`---
AWSTemplateFormatVersion: 2010-09-09
Resources:
  BadExample:
    Type: AWS::ECR::Repository
    Properties:
      RepositoryName: "test-repository"
      ImageScanningConfiguration:
        ScanOnPush: false
`},
		GoodExample: []string{`---
AWSTemplateFormatVersion: 2010-09-09
Resources:
  GoodExample:
    Type: AWS::ECR::Repository
    Properties:
      RepositoryName: "test-repository"
      ImageTagImmutability: IMMUTABLE
      ImageScanningConfiguration:
        ScanOnPush: true
      EncryptionConfiguration:
        EncryptionType: KMS
        KmsKey: "alias/ecr-key"
`},
		Base: ecr.CheckEnableImageScans,
	},
	)

}
