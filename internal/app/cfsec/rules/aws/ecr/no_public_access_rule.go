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
      RepositoryPolicyText: 
        Version: "2012-10-17"
        Statement: 
          - 
            Sid: AllowPushPull
            Effect: Allow
            Principal: 
              AWS: 
                - "*"
            Action: 
              - "ecr:GetDownloadUrlForLayer"
              - "ecr:BatchGetImage"
              - "ecr:BatchCheckLayerAvailability"
              - "ecr:PutImage"
              - "ecr:InitiateLayerUpload"
              - "ecr:UploadLayerPart"
              - "ecr:CompleteLayerUpload"
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
        ScanOnPush: false
      EncryptionConfiguration:
        EncryptionType: KMS
        KmsKey: "alias/ecr-key"
      RepositoryPolicyText: 
        Version: "2012-10-17"
        Statement: 
          - 
            Sid: AllowPushPull
            Effect: Allow
            Principal: 
              AWS: 
                - "arn:aws:iam::123456789012:user/Alice"
            Action: 
              - "ecr:GetDownloadUrlForLayer"
              - "ecr:BatchGetImage"
              - "ecr:BatchCheckLayerAvailability"
              - "ecr:PutImage"
              - "ecr:InitiateLayerUpload"
              - "ecr:UploadLayerPart"
              - "ecr:CompleteLayerUpload"
`},
		Base: ecr.CheckNoPublicAccess,
	},
	)

}
