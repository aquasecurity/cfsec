---
title: S3 Data should be versioned
shortcode: enable-versioning
summary: S3 Data should be versioned 
permalink: /docs/s3/enable-versioning/
---

### Explanation


Versioning in Amazon S3 is a means of keeping multiple variants of an object in the same bucket. 
You can use the S3 Versioning feature to preserve, retrieve, and restore every version of every object stored in your buckets. 
With versioning you can recover more easily from both unintended user actions and application failures.


### Possible Impact
Deleted or modified data would not be recoverable

### Suggested Resolution
Enable versioning to protect against accidental/malicious removal or modification


### Insecure Example

The following example will fail the AVD-AWS-0090 check.

```yaml
---
Resources:
  BadExample:
    Type: AWS::S3::Bucket

```



### Secure Example

The following example will pass the AVD-AWS-0090 check.

```yaml
---
Resources:
  GoodExample:
    Properties:
      VersioningConfiguration:
        Status: Enabled
    Type: AWS::S3::Bucket

```




### Related Links


- [https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html)


