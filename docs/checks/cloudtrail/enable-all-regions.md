---
title: Cloudtrail should be enabled in all regions regardless of where your AWS resources are generally homed
shortcode: enable-all-regions
summary: Cloudtrail should be enabled in all regions regardless of where your AWS resources are generally homed 
permalink: /docs/cloudtrail/enable-all-regions/
---

### Explanation

When creating Cloudtrail in the AWS Management Console the trail is configured by default to be multi-region, this isn't the case with the Terraform resource. Cloudtrail should cover the full AWS account to ensure you can track changes in regions you are not actively operting in.

### Possible Impact
Activity could be happening in your account in a different region

### Suggested Resolution
Enable Cloudtrail in all regions


### Insecure Example

The following example will fail the AVD-AWS-0014 check.

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

The following example will pass the AVD-AWS-0014 check.

```yaml
---
Resources:
  BadExample:
    Type: AWS::CloudTrail::Trail
    Properties:
      IsLogging: true
      IsMultiRegionTrail: true     
      S3BucketName: "CloudtrailBucket"
      S3KeyPrefix: "/trailing"
      TrailName: "Cloudtrail"

```




### Related Links


- [https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html)


