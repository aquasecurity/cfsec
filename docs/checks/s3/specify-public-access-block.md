---
title: S3 buckets should each define an aws_s3_bucket_public_access_block
shortcode: specify-public-access-block
summary: S3 buckets should each define an aws_s3_bucket_public_access_block 
permalink: /docs/s3/specify-public-access-block/
---

### Explanation

The "block public access" settings in S3 override individual policies that apply to a given bucket, meaning that all public access can be controlled in one central types for that bucket. It is therefore good practice to define these settings for each bucket in order to clearly define the public access that can be allowed for it.

### Possible Impact
Public access policies may be applied to sensitive data buckets

### Suggested Resolution
Define a aws_s3_bucket_public_access_block for the given bucket to control public access policies


### Insecure Example

The following example will fail the AVD-AWS-0094 check.

```yaml
---
Resources:
  BadExample:
    Properties:
      AccessControl: AuthenticatedRead
    Type: AWS::S3::Bucket

```



### Secure Example

The following example will pass the AVD-AWS-0094 check.

```yaml
---
Resources:
  GoodExample:
    Properties:
      AccessControl: Private
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
    Type: AWS::S3::Bucket

```




### Related Links


- [https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)


