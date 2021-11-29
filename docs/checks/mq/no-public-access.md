---
title: Ensure MQ Broker is not publicly exposed
shortcode: no-public-access
summary: Ensure MQ Broker is not publicly exposed 
permalink: /docs/mq/no-public-access/
---

### Explanation

Public access of the MQ broker should be disabled and only allow routes to applications that require access.

### Possible Impact
Publicly accessible MQ Broker may be vulnerable to compromise

### Suggested Resolution
Disable public access when not required


### Insecure Example

The following example will fail the AVD-AWS-0072 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example
Resources:
  Broker:
    Type: AWS::AmazonMQ::Broker
    Properties:
      PubliclyAccessible: true


```



### Secure Example

The following example will pass the AVD-AWS-0072 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example
Resources:
  Broker:
    Type: AWS::AmazonMQ::Broker
    Properties:
      PubliclyAccessible: false


```




### Related Links


- [https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/using-amazon-mq-securely.html#prefer-brokers-without-public-accessibility](https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/using-amazon-mq-securely.html#prefer-brokers-without-public-accessibility)


