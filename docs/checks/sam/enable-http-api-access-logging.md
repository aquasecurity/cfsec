---
title: SAM HTTP API stages for V1 and V2 should have access logging enabled
shortcode: enable-http-api-access-logging
summary: SAM HTTP API stages for V1 and V2 should have access logging enabled 
permalink: /docs/sam/enable-http-api-access-logging/
---

### Explanation

API Gateway stages should have access log settings block configured to track all access to a particular stage. This should be applied to both v1 and v2 gateway stages.

### Possible Impact
Logging provides vital information about access and usage

### Suggested Resolution
Enable logging for API Gateway stages


### Insecure Example

The following example will fail the AVD-AWS-0116 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad Example of SAM API
Resources:
  HttpApi:
    Type: AWS::Serverless::HttpApi
    Properties:
    Properties:
      Name: Good SAM API example
      StageName: Prod
      Tracing: Passthrough

```



### Secure Example

The following example will pass the AVD-AWS-0116 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Good Example of SAM API
Resources:
  ApiGatewayApi:
    Type: AWS::Serverless::HttpApi
    Properties:
      Name: Good SAM API example
      StageName: Prod
      Tracing: Activey
      AccessLogSetting:
        DestinationArn: gateway-logging
        Format: json

```




### Related Links


- [https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-httpapi.html#sam-httpapi-accesslogsettings](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-httpapi.html#sam-httpapi-accesslogsettings)


