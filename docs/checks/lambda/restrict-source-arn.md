---
title: Ensure that lambda function permission has a source arn specified
shortcode: restrict-source-arn
summary: Ensure that lambda function permission has a source arn specified 
permalink: /docs/lambda/restrict-source-arn/
---

### Explanation

When the principal is an AWS service, the ARN of the specific resource within that service to grant permission to. 

Without this, any resource from principal will be granted permission – even if that resource is from another account. 

For S3, this should be the ARN of the S3 Bucket. For CloudWatch Events, this should be the ARN of the CloudWatch Events Rule. For API Gateway, this should be the ARN of the API

### Possible Impact
Not providing the source ARN allows any resource from principal, even from other accounts

### Suggested Resolution
Always provide a source arn for Lambda permissions


### Insecure Example

The following example will fail the AVD-AWS-0067 check.

```yaml
---
Resources:
  BadExample:
    Type: AWS::Lambda::Function
    Properties:
      Handler: index.handler
      Role: arn:aws:iam::123456789012:role/lambda-role
      Code:
        S3Bucket: my-bucket
        S3Key: function.zip
      Runtime: nodejs12.x
      Timeout: 5
      TracingConfig:
        Mode: Active
      VpcConfig:
        SecurityGroupIds:
          - sg-085912345678492fb
        SubnetIds:
          - subnet-071f712345678e7c8
          - subnet-07fd123456788a036
  BadPermission:
    Type: AWS::Lambda::Permission
    Properties:
      FunctionName: !Ref BadExample
      Action: lambda:InvokeFunction
      Principal: s3.amazonaws.com


```



### Secure Example

The following example will pass the AVD-AWS-0067 check.

```yaml
---
Resources:
  GoodExample:
    Type: AWS::Lambda::Function
    Properties:
      Handler: index.handler
      Role: arn:aws:iam::123456789012:role/lambda-role
      Code:
        S3Bucket: my-bucket
        S3Key: function.zip
      Runtime: nodejs12.x
      Timeout: 5
      TracingConfig:
        Mode: Active
      VpcConfig:
        SecurityGroupIds:
          - sg-085912345678492fb
        SubnetIds:
          - subnet-071f712345678e7c8
          - subnet-07fd123456788a036
  GoodPermission:
    Type: AWS::Lambda::Permission
    Properties:
      FunctionName: !Ref BadExample
      Action: lambda:InvokeFunction
      Principal: s3.amazonaws.com
      SourceArn: "lambda.amazonaws.com"
  

```




### Related Links


- [https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-permission.html](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-permission.html)


