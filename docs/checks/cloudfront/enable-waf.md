---
title: CloudFront distribution does not have a WAF in front.
shortcode: enable-waf
summary: CloudFront distribution does not have a WAF in front. 
permalink: /docs/cloudfront/enable-waf/
---

### Explanation

You should configure a Web Application Firewall in front of your CloudFront distribution. This will mitigate many types of attacks on your web application.

### Possible Impact
Complex web application attacks can more easily be performed without a WAF

### Suggested Resolution
Enable WAF for the CloudFront distribution


### Insecure Example

The following example will fail the AVD-AWS-0011 check.

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
        Logging:
          Bucket: logging-bucket
        Origins:
          - DomainName: https://some.domain
            Id: somedomain1
    Type: AWS::CloudFront::Distribution

```



### Secure Example

The following example will pass the AVD-AWS-0011 check.

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
        WebACLId: waf_id
    Type: AWS::CloudFront::Distribution

```




### Related Links


- [https://docs.aws.amazon.com/waf/latest/developerguide/cloudfront-features.html](https://docs.aws.amazon.com/waf/latest/developerguide/cloudfront-features.html)


