---
title: Unencrypted SQS queue.
shortcode: enable-queue-encryption
summary: Unencrypted SQS queue. 
permalink: /docs/sqs/enable-queue-encryption/
---

### Explanation

Queues should be encrypted with customer managed KMS keys and not default AWS managed keys, in order to allow granular control over access to specific queues.

### Possible Impact
The SQS queue messages could be read if compromised

### Suggested Resolution
Turn on SQS Queue encryption


### Insecure Example

The following example will fail the AVD-AWS-0096 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of queue
Resources:
  Queue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: my-queue


```



### Secure Example

The following example will pass the AVD-AWS-0096 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of queue
Resources:
  Queue:
    Type: AWS::SQS::Queue
    Properties:
      KmsMasterKeyId: some-key
      QueueName: my-queue


```




### Related Links


- [https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html)


