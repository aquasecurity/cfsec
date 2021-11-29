---
title: S3 Access block should block public policy
shortcode: block-public-policy
summary: S3 Access block should block public policy 
permalink: /docs/s3/block-public-policy/
---

### Explanation


S3 bucket policy should have block public policy to prevent users from putting a policy that enable public access.


### Possible Impact
Users could put a policy that allows public access

### Suggested Resolution
Prevent policies that allow public access being PUT


### Insecure Example

The following example will fail the AVD-AWS-0087 check.

```yaml
---
Resources:
  BadExample:
    Properties:
      AccessControl: AuthenticatedRead
    Type: AWS::S3::Bucket

```



### Secure Example

The following example will pass the AVD-AWS-0087 check.

```yaml
---
Resources:
  GoodExample:
    Properties:
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
    Type: AWS::S3::Bucket

```




### Related Links


- [https://docs.aws.amazon.com/AmazonS3/latest/dev-retired/access-control-block-public-access.html](https://docs.aws.amazon.com/AmazonS3/latest/dev-retired/access-control-block-public-access.html)


