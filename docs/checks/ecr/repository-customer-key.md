---
title: ECR Repository should use customer managed keys to allow more control
shortcode: repository-customer-key
summary: ECR Repository should use customer managed keys to allow more control 
permalink: /docs/ecr/repository-customer-key/
---

### Explanation

Images in the ECR repository are encrypted by default using AWS managed encryption keys. To increase control of the encryption and control the management of factors like key rotation, use a Customer Managed Key.

### Possible Impact
Using AWS managed keys does not allow for fine grained control

### Suggested Resolution
Use customer managed keys


### Insecure Example

The following example will fail the AVD-AWS-0033 check.

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

The following example will pass the AVD-AWS-0033 check.

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

```




### Related Links


- [https://docs.aws.amazon.com/AmazonECR/latest/userguide/encryption-at-rest.html](https://docs.aws.amazon.com/AmazonECR/latest/userguide/encryption-at-rest.html)


