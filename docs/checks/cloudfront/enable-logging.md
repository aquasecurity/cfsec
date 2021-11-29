---
title: Cloudfront distribution should have Access Logging configured
shortcode: enable-logging
summary: Cloudfront distribution should have Access Logging configured 
permalink: /docs/cloudfront/enable-logging/
---

### Explanation

You should configure CloudFront Access Logging to create log files that contain detailed information about every user request that CloudFront receives

### Possible Impact
Logging provides vital information about access and usage

### Suggested Resolution
Enable logging for CloudFront distributions


### Insecure Example

The following example will fail the AVD-AWS-0010 check.

```yaml
---
Resources:
  BadExample:
    Properties:
      DistributionConfig:
        DefaultCacheBehavior:
          TargetOriginId: target
          ViewerProtocolPolicy: https-only
        Enabled: true
        Origins:
          - DomainName: https://some.domain
            Id: somedomain1
    Type: AWS::CloudFront::Distribution

```



### Secure Example

The following example will pass the AVD-AWS-0010 check.

```yaml
---
Resources:
  GoodExample:
    Properties:
      DistributionConfig:
        DefaultCacheBehavior:
          TargetOriginId: target
          ViewerProtocolPolicy: https-only
        Enabled: true
        Logging:
          Bucket: logging-bucket
        Origins:
          - DomainName: https://some.domain
            Id: somedomain1
    Type: AWS::CloudFront::Distribution

```




### Related Links


- [https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html)


