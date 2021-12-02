---
title: State machine policies should avoid use of wildcards and instead apply the principle of least privilege
shortcode: no-state-machine-policy-wildcards
summary: State machine policies should avoid use of wildcards and instead apply the principle of least privilege 
permalink: /docs/sam/no-state-machine-policy-wildcards/
---

### Explanation

You should use the principle of least privilege when defining your IAM policies. This means you should specify each exact permission required without using wildcards, as this could cause the granting of access to certain undesired actions, resources and principals.

### Possible Impact
Overly permissive policies may grant access to sensitive resources

### Suggested Resolution
Specify the exact permissions required, and to which resources they should apply instead of using wildcards.


### Insecure Example

The following example will fail the AVD-AWS-0120 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad Example of SAM Function
Resources:
  BadFunction:
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
      Policies:  
        - AWSLambdaExecute
        - Version: '2012-10-17'
          Statement:
          - Effect: Allow
            Action:
            - s3:*
            Resource: 'arn:aws:s3:::my-bucket/*'

```



### Secure Example

The following example will pass the AVD-AWS-0120 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Good Example of SAM Function
Resources:
  GoodFunction:
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
      Policies:  
        - AWSLambdaExecute
        - Version: '2012-10-17'
          Statement:
          - Effect: Allow
            Action:
            - s3:GetObject
            - s3:GetObjectACL
            Resource: 'arn:aws:s3:::my-bucket/*'

```




### Related Links


- [https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-statemachine.html#sam-statemachine-policies](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-statemachine.html#sam-statemachine-policies)


