---
title: Unencrypted SNS topic.
shortcode: enable-topic-encryption
summary: Unencrypted SNS topic. 
permalink: /docs/sns/enable-topic-encryption/
---

### Explanation

Queues should be encrypted with customer managed KMS keys and not default AWS managed keys, in order to allow granular control over access to specific queues.

### Possible Impact
The SNS topic messages could be read if compromised

### Suggested Resolution
Turn on SNS Topic encryption


### Insecure Example

The following example will fail the AVD-AWS-0095 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of topic
Resources:
  Queue:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: blah


```



### Secure Example

The following example will pass the AVD-AWS-0095 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of topic
Resources:
  Queue:
    Type: AWS::SQS::Topic
    Properties:
      TopicName: blah
      KmsMasterKeyId: some-key


```




### Related Links


- [https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html](https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html)


