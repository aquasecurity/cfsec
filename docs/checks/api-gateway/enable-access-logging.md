---
title: API Gateway stages for V1 and V2 should have access logging enabled
shortcode: enable-access-logging
summary: API Gateway stages for V1 and V2 should have access logging enabled 
permalink: /docs/api-gateway/enable-access-logging/
---

### Explanation

API Gateway stages should have access log settings block configured to track all access to a particular stage. This should be applied to both v1 and v2 gateway stages.

### Possible Impact
Logging provides vital information about access and usage

### Suggested Resolution
Enable logging for API Gateway stages


### Insecure Example

The following example will fail the AVD-AWS-0001 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad Example of ApiGateway
Resources:
  BadApi:
    Type: AWS::ApiGatewayV2::Api
  BadApiStage:
    Type: AWS::ApiGatewayV2::Stage
    Properties:
      AccessLogSettings:
        Format: json
      ApiId: !Ref BadApi
      StageName: BadApiStage

```



### Secure Example

The following example will pass the AVD-AWS-0001 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Good Example of ApiGateway
Resources:
  GoodApi:
    Type: AWS::ApiGatewayV2::Api
  GoodApiStage:
    Type: AWS::ApiGatewayV2::Stage
    Properties:
      AccessLogSettings:
        DestinationArn: gateway-logging
        Format: json
      ApiId: !Ref GoodApi
      StageName: GoodApiStage

```




### Related Links


- [https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html](https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html)


