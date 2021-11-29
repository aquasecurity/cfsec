---
title: S3 Access block should restrict public bucket to limit access
shortcode: no-public-buckets
summary: S3 Access block should restrict public bucket to limit access 
permalink: /docs/s3/no-public-buckets/
---

### Explanation

S3 buckets should restrict public policies for the bucket. By enabling, the restrict_public_buckets, only the bucket owner and AWS Services can access if it has a public policy.

### Possible Impact
Public buckets can be accessed by anyone

### Suggested Resolution
Limit the access to public buckets to only the owner or AWS Services (eg; CloudFront)


### Insecure Example

The following example will fail the AVD-AWS-0093 check.

```yaml
---
Resources:
  BadExample:
    Properties:
      AccessControl: AuthenticatedRead
    Type: AWS::S3::Bucket

```



### Secure Example

The following example will pass the AVD-AWS-0093 check.

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


