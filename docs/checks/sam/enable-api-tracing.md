---
title: SAM API must have X-Ray tracing enabled
shortcode: enable-api-tracing
summary: SAM API must have X-Ray tracing enabled 
permalink: /docs/sam/enable-api-tracing/
---

### Explanation

X-Ray tracing enables end-to-end debugging and analysis of all API Gateway HTTP requests.

### Possible Impact
Without full tracing enabled it is difficult to trace the flow of logs

### Suggested Resolution
Enable tracing


### Insecure Example

The following example will fail the AVD-AWS-0111 check.

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

The following example will pass the AVD-AWS-0111 check.

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
      TracingEnabled: true

```




### Related Links


- [https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-api.html#sam-api-tracingenabled](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-api.html#sam-api-tracingenabled)


