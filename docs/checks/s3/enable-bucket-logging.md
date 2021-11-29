---
title: S3 Bucket does not have logging enabled.
shortcode: enable-bucket-logging
summary: S3 Bucket does not have logging enabled. 
permalink: /docs/s3/enable-bucket-logging/
---

### Explanation

Buckets should have logging enabled so that access can be audited.

### Possible Impact
There is no way to determine the access to this bucket

### Suggested Resolution
Add a logging block to the resource to enable access logging


### Insecure Example

The following example will fail the AVD-AWS-0089 check.

```yaml
---
Resources:
  DisabledEncryptionBucket:
    Properties:
    Type: AWS::S3::Bucket

```



### Secure Example

The following example will pass the AVD-AWS-0089 check.

```yaml
---
Resources:
  GoodExample:
    Properties:
      LoggingConfiguration:
        DestinationBucketName: logging-bucket
        LogFilePrefix: accesslogs/
    Type: AWS::S3::Bucket

```




### Related Links


- [https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html](https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html)


