---
title: SAM State machine must have X-Ray tracing enabled
shortcode: enable-state-machine-tracing
summary: SAM State machine must have X-Ray tracing enabled 
permalink: /docs/sam/enable-state-machine-tracing/
---

### Explanation

X-Ray tracing enables end-to-end debugging and analysis of all state machine activities.

### Possible Impact
Without full tracing enabled it is difficult to trace the flow of logs

### Suggested Resolution
Enable tracing


### Insecure Example

The following example will fail the AVD-AWS-0117 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad Example of SAM API
Resources:
  BadStateMachine:
    Type: AWS::Serverless::StateMachine
    Properties:
      Definition:
        StartAt: MyLambdaState
        States:
          MyLambdaState:
            Type: Task
            Resource: arn:aws:lambda:us-east-1:123456123456:function:my-sample-lambda-app
            End: true
      Role: arn:aws:iam::123456123456:role/service-role/my-sample-role
      Tracing:
        Enabled: false

```



### Secure Example

The following example will pass the AVD-AWS-0117 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Good Example of SAM API
Resources:
  GoodStateMachine:
    Type: AWS::Serverless::StateMachine
    Properties:
      Definition:
        StartAt: MyLambdaState
        States:
          MyLambdaState:
            Type: Task
            Resource: arn:aws:lambda:us-east-1:123456123456:function:my-sample-lambda-app
            End: true
      Role: arn:aws:iam::123456123456:role/service-role/my-sample-role
      Tracing:
        Enabled: true

```




### Related Links


- [https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-statemachine.html#sam-statemachine-tracing](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-statemachine.html#sam-statemachine-tracing)


