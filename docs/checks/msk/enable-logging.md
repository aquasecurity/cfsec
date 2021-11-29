---
title: Ensure MSK Cluster logging is enabled
shortcode: enable-logging
summary: Ensure MSK Cluster logging is enabled 
permalink: /docs/msk/enable-logging/
---

### Explanation

Managed streaming for Kafka can log to Cloud Watch, Kinesis Firehose and S3, at least one of these locations should be logged to

### Possible Impact
Without logging it is difficult to trace issues

### Suggested Resolution
Enable logging


### Insecure Example

The following example will fail the AVD-AWS-0074 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example
Resources:
  Cluster:
    Type: AWS::MSK::Cluster
    Properties:
      LoggingInfo:
        BrokerLogs:
          CloudWatchLogs:
            Enabled: false


```



### Secure Example

The following example will pass the AVD-AWS-0074 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example
Resources:
  Cluster:
    Type: AWS::MSK::Cluster
    Properties:
      LoggingInfo:
        BrokerLogs:
          S3:
            Enabled: true



```




### Related Links


- [https://docs.aws.amazon.com/msk/latest/developerguide/msk-logging.html](https://docs.aws.amazon.com/msk/latest/developerguide/msk-logging.html)


