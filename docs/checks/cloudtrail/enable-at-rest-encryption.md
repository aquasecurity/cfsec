---
title: Cloudtrail should be encrypted at rest to secure access to sensitive trail data
shortcode: enable-at-rest-encryption
summary: Cloudtrail should be encrypted at rest to secure access to sensitive trail data 
permalink: /docs/cloudtrail/enable-at-rest-encryption/
---

### Explanation

Cloudtrail logs should be encrypted at rest to secure the sensitive data. Cloudtrail logs record all activity that occurs in the the account through API calls and would be one of the first places to look when reacting to a breach.

### Possible Impact
Data can be freely read if compromised

### Suggested Resolution
Enable encryption at rest


### Insecure Example

The following example will fail the AVD-AWS-0015 check.

```yaml
---
Resources:
  BadExample:
    Type: AWS::CloudTrail::Trail
    Properties:
      IsLogging: true
      IsMultiRegionTrail: false     
      S3BucketName: "CloudtrailBucket"
      S3KeyPrefix: "/trailing"
      TrailName: "Cloudtrail"

```



### Secure Example

The following example will pass the AVD-AWS-0015 check.

```yaml
---
Resources:
  BadExample:
    Type: AWS::CloudTrail::Trail
    Properties:
      IsLogging: true
      IsMultiRegionTrail: true
      KmsKeyId: "alias/CloudtrailKey"
      S3BucketName: "CloudtrailBucket"
      S3KeyPrefix: "/trailing"
      TrailName: "Cloudtrail"

```




### Related Links


- [https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html)


