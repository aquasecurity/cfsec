---
title: SAM Function must have X-Ray tracing enabled
shortcode: enable-function-tracing
summary: SAM Function must have X-Ray tracing enabled 
permalink: /docs/sam/enable-function-tracing/
---

### Explanation

X-Ray tracing enables end-to-end debugging and analysis of the function.

### Possible Impact
Without full tracing enabled it is difficult to trace the flow of logs

### Suggested Resolution
Enable tracing


### Insecure Example

The following example will fail the AVD-AWS-0113 check.

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

```



### Secure Example

The following example will pass the AVD-AWS-0113 check.

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
      Tracing: Active

```




### Related Links


- [https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-function.html#sam-function-tracing](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-function.html#sam-function-tracing)


