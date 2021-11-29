---
title: Kinesis stream is unencrypted.
shortcode: enable-in-transit-encryption
summary: Kinesis stream is unencrypted. 
permalink: /docs/kinesis/enable-in-transit-encryption/
---

### Explanation

Kinesis streams should be encrypted to ensure sensitive data is kept private. Additionally, non-default KMS keys should be used so granularity of access control can be ensured.

### Possible Impact
Intercepted data can be read in transit

### Suggested Resolution
Enable in transit encryption


### Insecure Example

The following example will fail the AVD-AWS-0064 check.

```yaml
---
Resources:
  BadExample:
    Type: AWS::Kinesis::Stream
    Properties:
      Name: BadExample
      RetentionPeriodHours: 168
      ShardCount: 3
      Tags:
        -
          Key: Environment 
          Value: Production


```



### Secure Example

The following example will pass the AVD-AWS-0064 check.

```yaml
---
Resources:
  GoodExample:
    Type: AWS::Kinesis::Stream
    Properties:
      Name: GoodExample
      RetentionPeriodHours: 168
      ShardCount: 3
      StreamEncryption:
        EncryptionType: KMS
        KeyId: alis/key
      Tags:
        -
          Key: Environment 
          Value: Production

```




### Related Links


- [https://docs.aws.amazon.com/streams/latest/dev/server-side-encryption.html](https://docs.aws.amazon.com/streams/latest/dev/server-side-encryption.html)


