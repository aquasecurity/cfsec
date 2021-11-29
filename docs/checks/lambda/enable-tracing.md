---
title: Lambda functions should have X-Ray tracing enabled
shortcode: enable-tracing
summary: Lambda functions should have X-Ray tracing enabled 
permalink: /docs/lambda/enable-tracing/
---

### Explanation

X-Ray tracing enables end-to-end debugging and analysis of all function activity. This will allow for identifying bottlenecks, slow downs and timeouts.

### Possible Impact
WIthout full tracing enabled it is difficult to trace the flow of logs

### Suggested Resolution
Enable tracing


### Insecure Example

The following example will fail the AVD-AWS-0066 check.

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
      VpcConfig:
        SecurityGroupIds:
          - sg-085912345678492fb
        SubnetIds:
          - subnet-071f712345678e7c8
          - subnet-07fd123456788a036
```



### Secure Example

The following example will pass the AVD-AWS-0066 check.

```yaml
---
Resources:
  Function:
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
```




### Related Links


- [https://docs.aws.amazon.com/lambda/latest/dg/services-xray.html](https://docs.aws.amazon.com/lambda/latest/dg/services-xray.html)


