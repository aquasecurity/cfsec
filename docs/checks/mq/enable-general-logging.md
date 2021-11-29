---
title: MQ Broker should have general logging enabled
shortcode: enable-general-logging
summary: MQ Broker should have general logging enabled 
permalink: /docs/mq/enable-general-logging/
---

### Explanation

Logging should be enabled to allow tracing of issues and activity to be investigated more fully. Logs provide additional information and context which is often invalauble during investigation

### Possible Impact
Without logging it is difficult to trace issues

### Suggested Resolution
Enable general logging


### Insecure Example

The following example will fail the AVD-AWS-0071 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example
Resources:
  Broker:
    Type: AWS::AmazonMQ::Broker
    Properties:
      Logs:
        General: false


```



### Secure Example

The following example will pass the AVD-AWS-0071 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example
Resources:
  Broker:
    Type: AWS::AmazonMQ::Broker
    Properties:
      Logs:
        General: true


```




### Related Links


- [https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/configure-logging-monitoring-activemq.html](https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/configure-logging-monitoring-activemq.html)


