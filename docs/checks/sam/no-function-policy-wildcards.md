---
title: Function policies should avoid use of wildcards and instead apply the principle of least privilege
shortcode: no-function-policy-wildcards
summary: Function policies should avoid use of wildcards and instead apply the principle of least privilege 
permalink: /docs/sam/no-function-policy-wildcards/
---

### Explanation

You should use the principle of least privilege when defining your IAM policies. This means you should specify each exact permission required without using wildcards, as this could cause the granting of access to certain undesired actions, resources and principals.

### Possible Impact
Overly permissive policies may grant access to sensitive resources

### Suggested Resolution
Specify the exact permissions required, and to which resources they should apply instead of using wildcards.


### Insecure Example

The following example will fail the AVD-AWS-0114 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad Example of SAM Function
Resources:
  BadFunction:
    Type: AWS::Serverless::Function
    Properties:
      PackageType: Image
      ImageUri: account-id.dkr.ecr.region.amazonaws.com/ecr-repo-name:image-name
      ImageConfig:
        Command:
          - "app.lambda_handler"
        EntryPoint:
          - "entrypoint1"
        WorkingDirectory: "workDir"
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

The following example will pass the AVD-AWS-0114 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Good Example of SAM Function
Resources:
  GoodFunction:
    Type: AWS::Serverless::Function
    Properties:
      PackageType: Image
      ImageUri: account-id.dkr.ecr.region.amazonaws.com/ecr-repo-name:image-name
      ImageConfig:
        Command:
          - "app.lambda_handler"
        EntryPoint:
          - "entrypoint1"
        WorkingDirectory: "workDir"
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


- [https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-function.html#sam-function-policies](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-function.html#sam-function-policies)


