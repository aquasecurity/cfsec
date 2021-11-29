---
title: CloudFront distribution allows unencrypted (HTTP) communications.
shortcode: enforce-https
summary: CloudFront distribution allows unencrypted (HTTP) communications. 
permalink: /docs/cloudfront/enforce-https/
---

### Explanation

Plain HTTP is unencrypted and human-readable. This means that if a malicious actor was to eavesdrop on your connection, they would be able to see all of your data flowing back and forth.

You should use HTTPS, which is HTTP over an encrypted (TLS) connection, meaning eavesdroppers cannot read your traffic.

### Possible Impact
CloudFront is available through an unencrypted connection

### Suggested Resolution
Only allow HTTPS for CloudFront distribution communication


### Insecure Example

The following example will fail the AVD-AWS-0012 check.

```yaml
---
Resources:
  BadExample:
    Properties:
      DistributionConfig:
        DefaultCacheBehavior:
          TargetOriginId: target
          ViewerProtocolPolicy: allow-all
        Enabled: true
        Logging:
          Bucket: logging-bucket
        Origins:
          - DomainName: https://some.domain
            Id: somedomain1
        WebACLId: waf_id
    Type: AWS::CloudFront::Distribution

```



### Secure Example

The following example will pass the AVD-AWS-0012 check.

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


- [https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-cloudfront-to-s3-origin.html](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-cloudfront-to-s3-origin.html)


