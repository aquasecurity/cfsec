---
title: Unencrypted S3 bucket.
shortcode: enable-bucket-encryption
summary: Unencrypted S3 bucket. 
permalink: /docs/s3/enable-bucket-encryption/
---

### Explanation


S3 Buckets should be encrypted with customer managed KMS keys and not default AWS managed keys, in order to allow granular control over access to specific buckets.


### Possible Impact
The bucket objects could be read if compromised

### Suggested Resolution
Configure bucket encryption


### Insecure Example

The following example will fail the AVD-AWS-0088 check.

```yaml
---
Resources:
  BadExample:
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - BucketKeyEnabled: false
            ServerSideEncryptionByDefault:
              KMSMasterKeyID: asdf
              SSEAlgorithm: asdf
    Type: AWS::S3::Bucket

```



### Secure Example

The following example will pass the AVD-AWS-0088 check.

```yaml

Resources:
  GoodExample:
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - BucketKeyEnabled: true
            ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256
    Type: AWS::S3::Bucket

```




### Related Links


- [https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html)


