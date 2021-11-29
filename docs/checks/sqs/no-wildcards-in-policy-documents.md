---
title: AWS SQS policy document has wildcard action statement.
shortcode: no-wildcards-in-policy-documents
summary: AWS SQS policy document has wildcard action statement. 
permalink: /docs/sqs/no-wildcards-in-policy-documents/
---

### Explanation

SQS Policy actions should always be restricted to a specific set.

This ensures that the queue itself cannot be modified or deleted, and prevents possible future additions to queue actions to be implicitly allowed.

### Possible Impact
SQS policies with wildcard actions allow more that is required

### Suggested Resolution
Keep policy scope to the minimum that is required to be effective


### Insecure Example

The following example will fail the AVD-AWS-0097 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of queue policy
Resources:
  MyQueue:
    Type: AWS::SQS::Queue
    Properties:
      Name: something
  SampleSQSPolicy: 
    Type: AWS::SQS::QueuePolicy
    Properties: 
      Queues: 
        - !Ref MyQueue
      PolicyDocument: 
        Statement: 
          - 
            Action: 
              - "*" 
            Effect: "Allow"
            Resource: "arn:aws:sqs:us-east-2:444455556666:queue2"
            Principal:  
              AWS: 
                - "111122223333"        

```



### Secure Example

The following example will pass the AVD-AWS-0097 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of queue policy
Resources:
  MyQueue:
    Type: AWS::SQS::Queue
    Properties:
      Name: something
  SampleSQSPolicy: 
    Type: AWS::SQS::QueuePolicy
    Properties: 
      Queues: 
        - Ref: MyQueue
      PolicyDocument: 
        Statement: 
          - 
            Action: 
              - "SQS:SendMessage" 
              - "SQS:ReceiveMessage"
            Effect: "Allow"
            Resource: "arn:aws:sqs:us-east-2:444455556666:queue2"
            Principal:  
              AWS: 
                - "111122223333"        

```




### Related Links


- [https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-security-best-practices.html](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-security-best-practices.html)


