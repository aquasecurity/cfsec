---
title: CloudWatch log groups should be encrypted using CMK
shortcode: log-group-customer-key
summary: CloudWatch log groups should be encrypted using CMK 
permalink: /docs/cloudwatch/log-group-customer-key/
---

### Explanation

CloudWatch log groups are encrypted by default, however, to get the full benefit of controlling key rotation and other KMS aspects a KMS CMK should be used.

### Possible Impact
Log data may be leaked if the logs are compromised. No auditing of who have viewed the logs.

### Suggested Resolution
Enable CMK encryption of CloudWatch Log Groups


### Insecure Example

The following example will fail the AVD-AWS-0017 check.

```yaml
---
Resources:
  BadExample:
    Type: AWS::Logs::LogGroup
    Properties:
      KmsKeyId: ""
      LogGroupName: "aws/lambda/badExample"
      RetentionInDays: 30

```



### Secure Example

The following example will pass the AVD-AWS-0017 check.

```yaml
---
Resources:
  GoodExample:
    Type: AWS::Logs::LogGroup
    Properties:
      KmsKeyId: "arn:aws:kms:us-west-2:111122223333:key/lambdalogging"
      LogGroupName: "aws/lambda/goodExample"
      RetentionInDays: 30

```




### Related Links


- [https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html)


