---
title: S3 Access block should block public ACL
shortcode: block-public-acls
summary: S3 Access block should block public ACL 
permalink: /docs/s3/block-public-acls/
---

### Explanation


S3 buckets should block public ACLs on buckets and any objects they contain. By blocking, PUTs with fail if the object has any public ACL a.


### Possible Impact
PUT calls with public ACLs specified can make objects public

### Suggested Resolution
Enable blocking any PUT calls with a public ACL specified


### Insecure Example

The following example will fail the AVD-AWS-0086 check.

```yaml
---
Resources:
  BadExample:
    Properties:
      AccessControl: AuthenticatedRead
    Type: AWS::S3::Bucket

```



### Secure Example

The following example will pass the AVD-AWS-0086 check.

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


- [https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)


