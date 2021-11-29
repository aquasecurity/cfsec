---
title: S3 Bucket does not have logging enabled.
shortcode: no-public-access-with-acl
summary: S3 Bucket does not have logging enabled. 
permalink: /docs/s3/no-public-access-with-acl/
---

### Explanation


Buckets should have logging enabled so that access can be audited. 


### Possible Impact
There is no way to determine the access to this bucket

### Suggested Resolution
Add a logging block to the resource to enable access logging


### Insecure Example

The following example will fail the AVD-AWS-0092 check.

```yaml
---
Resources:
  BadExample:
    Properties:
      AccessControl: AuthenticatedRead
    Type: AWS::S3::Bucket

```



### Secure Example

The following example will pass the AVD-AWS-0092 check.

```yaml
---
Resources:
  GoodExample:
    Properties:
      AccessControl: Private
    Type: AWS::S3::Bucket

```




### Related Links


- [https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html](https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html)


