---
title: Athena databases and workgroup configurations are created unencrypted at rest by default, they should be encrypted
shortcode: enable-at-rest-encryption
summary: Athena databases and workgroup configurations are created unencrypted at rest by default, they should be encrypted 
permalink: /docs/athena/enable-at-rest-encryption/
---

### Explanation

Athena databases and workspace result sets should be encrypted at rests. These databases and query sets are generally derived from data in S3 buckets and should have the same level of at rest protection.

### Possible Impact
Data can be read if the Athena Database is compromised

### Suggested Resolution
Enable encryption at rest for Athena databases and workgroup configurations


### Insecure Example

The following example will fail the AVD-AWS-0006 check.

```yaml
---
Resources:
  BadExample:
    Properties:
      Name: badExample
      WorkGroupConfiguration:
        ResultConfiguration:
    Type: AWS::Athena::WorkGroup

```



### Secure Example

The following example will pass the AVD-AWS-0006 check.

```yaml
---
Resources:
  GoodExample:
    Properties:
      Name: goodExample
      WorkGroupConfiguration:
        ResultConfiguration:
          EncryptionConfiguration:
            EncryptionOption: SSE_KMS
    Type: AWS::Athena::WorkGroup

```




### Related Links


- [https://docs.aws.amazon.com/athena/latest/ug/encryption.html](https://docs.aws.amazon.com/athena/latest/ug/encryption.html)


