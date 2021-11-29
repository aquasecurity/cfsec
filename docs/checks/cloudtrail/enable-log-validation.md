---
title: Cloudtrail log validation should be enabled to prevent tampering of log data
shortcode: enable-log-validation
summary: Cloudtrail log validation should be enabled to prevent tampering of log data 
permalink: /docs/cloudtrail/enable-log-validation/
---

### Explanation

Log validation should be activated on Cloudtrail logs to prevent the tampering of the underlying data in the S3 bucket. It is feasible that a rogue actor compromising an AWS account might want to modify the log data to remove trace of their actions.

### Possible Impact
Illicit activity could be removed from the logs

### Suggested Resolution
Turn on log validation for Cloudtrail


### Insecure Example

The following example will fail the AVD-AWS-0016 check.

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

The following example will pass the AVD-AWS-0016 check.

```yaml
---
Resources:
  BadExample:
    Type: AWS::CloudTrail::Trail
    Properties:
      IsLogging: true
      IsMultiRegionTrail: true
      EnableLogFileValidation: true
      S3BucketName: "CloudtrailBucket"
      S3KeyPrefix: "/trailing"
      TrailName: "Cloudtrail"

```




### Related Links


- [https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html)


