---
title: MQ Broker should have audit logging enabled
shortcode: enable-audit-logging
summary: MQ Broker should have audit logging enabled 
permalink: /docs/mq/enable-audit-logging/
---

### Explanation

Logging should be enabled to allow tracing of issues and activity to be investigated more fully. Logs provide additional information and context which is often invalauble during investigation

### Possible Impact
Without audit logging it is difficult to trace activity in the MQ broker

### Suggested Resolution
Enable audit logging


### Insecure Example

The following example will fail the AVD-AWS-0070 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example
Resources:
  Broker:
    Type: AWS::AmazonMQ::Broker
    Properties:
      Logs:
        Audit: false


```



### Secure Example

The following example will pass the AVD-AWS-0070 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example
Resources:
  Broker:
    Type: AWS::AmazonMQ::Broker
    Properties:
      Logs:
        Audit: true


```




### Related Links


- [https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/configure-logging-monitoring-activemq.html](https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/configure-logging-monitoring-activemq.html)


