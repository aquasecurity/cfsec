---
title: S3 Access Block should Ignore Public Acl
shortcode: ignore-public-acls
summary: S3 Access Block should Ignore Public Acl 
permalink: /docs/s3/ignore-public-acls/
---

### Explanation


S3 buckets should ignore public ACLs on buckets and any objects they contain. By ignoring rather than blocking, PUT calls with public ACLs will still be applied but the ACL will be ignored.


### Possible Impact
PUT calls with public ACLs specified can make objects public

### Suggested Resolution
Enable ignoring the application of public ACLs in PUT calls


### Insecure Example

The following example will fail the AVD-AWS-0091 check.

```yaml
---
Resources:
  BadExample:
    Properties:
      AccessControl: AuthenticatedRead
    Type: AWS::S3::Bucket

```



### Secure Example

The following example will pass the AVD-AWS-0091 check.

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


