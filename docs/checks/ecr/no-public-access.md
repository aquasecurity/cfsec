---
title: ECR repository policy must block public access
shortcode: no-public-access
summary: ECR repository policy must block public access 
permalink: /docs/ecr/no-public-access/
---

### Explanation

Allowing public access to the ECR repository risks leaking sensitive of abusable information

### Possible Impact
Risk of potential data leakage of sensitive artifacts

### Suggested Resolution
Do not allow public access in the policy


### Insecure Example

The following example will fail the AVD-AWS-0032 check.

```yaml
---
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

```



### Secure Example

The following example will pass the AVD-AWS-0032 check.

```yaml
---
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

```




### Related Links


- [https://docs.aws.amazon.com/AmazonECR/latest/public/public-repository-policies.html](https://docs.aws.amazon.com/AmazonECR/latest/public/public-repository-policies.html)


