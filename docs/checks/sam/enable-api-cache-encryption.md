---
title: SAM API must have data cache enabled
shortcode: enable-api-cache-encryption
summary: SAM API must have data cache enabled 
permalink: /docs/sam/enable-api-cache-encryption/
---

### Explanation

Method cache encryption ensures that any sensitive data in the cache is not vulnerable to compromise in the event of interception

### Possible Impact
Data stored in the cache that is unencrypted may be vulnerable to compromise

### Suggested Resolution
Enable cache encryption


### Insecure Example

The following example will fail the AVD-AWS-0110 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad Example of SAM API
Resources:
  ApiGatewayApi:
    Type: AWS::Serverless::Api
    Properties:
      Name: Bad SAM API example
      StageName: Prod
      TracingEnabled: false

```



### Secure Example

The following example will pass the AVD-AWS-0110 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Good Example of SAM API
Resources:
  ApiGatewayApi:
    Type: AWS::Serverless::Api
    Properties:
      Name: Good SAM API example
      StageName: Prod
      TracingEnabled: false
      Domain:
        SecurityPolicy: TLS_1_2
      MethodSettings:
        CacheDataEncrypted: true

```




### Related Links


- [https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-apigateway-stage-methodsetting.html#cfn-apigateway-stage-methodsetting-cachedataencrypted](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-apigateway-stage-methodsetting.html#cfn-apigateway-stage-methodsetting-cachedataencrypted)


