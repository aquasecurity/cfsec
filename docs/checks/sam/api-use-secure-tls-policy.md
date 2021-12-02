---
title: SAM API domain name uses outdated SSL/TLS protocols.
shortcode: api-use-secure-tls-policy
summary: SAM API domain name uses outdated SSL/TLS protocols. 
permalink: /docs/sam/api-use-secure-tls-policy/
---

### Explanation

You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.

### Possible Impact
Outdated SSL policies increase exposure to known vulnerabilities

### Suggested Resolution
Use the most modern TLS/SSL policies available


### Insecure Example

The following example will fail the AVD-AWS-0112 check.

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

The following example will pass the AVD-AWS-0112 check.

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

```




### Related Links


- [https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-property-api-domainconfiguration.html#sam-api-domainconfiguration-securitypolicy](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-property-api-domainconfiguration.html#sam-api-domainconfiguration-securitypolicy)


