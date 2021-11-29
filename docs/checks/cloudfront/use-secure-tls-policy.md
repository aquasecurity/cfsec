---
title: CloudFront distribution uses outdated SSL/TLS protocols.
shortcode: use-secure-tls-policy
summary: CloudFront distribution uses outdated SSL/TLS protocols. 
permalink: /docs/cloudfront/use-secure-tls-policy/
---

### Explanation

You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.

### Possible Impact
Outdated SSL policies increase exposure to known vulnerabilities

### Suggested Resolution
Use the most modern TLS/SSL policies available


### Insecure Example

The following example will fail the AVD-AWS-0013 check.

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
        ViewerCertificate:
          MinimumProtocolVersion: TLSv1.0
    Type: AWS::CloudFront::Distribution

```



### Secure Example

The following example will pass the AVD-AWS-0013 check.

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
        ViewerCertificate:
          MinimumProtocolVersion: TLSv1.2_2021
    Type: AWS::CloudFront::Distribution

```




### Related Links


- [https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html)


