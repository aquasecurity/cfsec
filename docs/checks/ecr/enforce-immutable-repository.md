---
title: ECR images tags shouldn't be mutable.
shortcode: enforce-immutable-repository
summary: ECR images tags shouldn't be mutable. 
permalink: /docs/ecr/enforce-immutable-repository/
---

### Explanation

ECR images should be set to IMMUTABLE to prevent code injection through image mutation.

This can be done by setting <code>image_tab_mutability</code> to <code>IMMUTABLE</code>

### Possible Impact
Image tags could be overwritten with compromised images

### Suggested Resolution
Only use immutable images in ECR


### Insecure Example

The following example will fail the AVD-AWS-0031 check.

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

The following example will pass the AVD-AWS-0031 check.

```yaml
---
Resources:
  GoodExample:
    Type: AWS::ECR::Repository
    Properties:
      RepositoryName: "test-repository"
      ImageTagMutability: IMMUTABLE
      ImageScanningConfiguration:
        ScanOnPush: false
      EncryptionConfiguration:
        EncryptionType: KMS
        KmsKey: "alias/ecr-key"

```




### Related Links


- [https://sysdig.com/blog/toctou-tag-mutability/](https://sysdig.com/blog/toctou-tag-mutability/)


