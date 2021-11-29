---
title: ECR repository has image scans disabled.
shortcode: enable-image-scans
summary: ECR repository has image scans disabled. 
permalink: /docs/ecr/enable-image-scans/
---

### Explanation

Repository image scans should be enabled to ensure vulnerable software can be discovered and remediated as soon as possible.

### Possible Impact
The ability to scan images is not being used and vulnerabilities will not be highlighted

### Suggested Resolution
Enable ECR image scanning


### Insecure Example

The following example will fail the AVD-AWS-0030 check.

```yaml
---
Resources:
  BadExample:
    Type: AWS::ECR::Repository
    Properties:
      RepositoryName: "test-repository"
      ImageScanningConfiguration:
        ScanOnPush: false

```



### Secure Example

The following example will pass the AVD-AWS-0030 check.

```yaml
---
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

```




### Related Links


- [https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html](https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html)


