---
title: Encryption for RDS Performance Insights should be enabled.
shortcode: enable-performance-insights
summary: Encryption for RDS Performance Insights should be enabled. 
permalink: /docs/rds/enable-performance-insights/
---

### Explanation

When enabling Performance Insights on an RDS cluster or RDS DB Instance, and encryption key should be provided.

The encryption key specified in `performance_insights_kms_key_id` references a KMS ARN

### Possible Impact
Data can be read from the RDS Performance Insights if it is compromised

### Suggested Resolution
Enable encryption for RDS clusters and instances


### Insecure Example

The following example will fail the AVD-AWS-0078 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example
Resources:
  Queue:
    Type: AWS::RDS::DBInstance
    Properties:
      EnablePerformanceInsights: false


```



### Secure Example

The following example will pass the AVD-AWS-0078 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example
Resources:
  Queue:
    Type: AWS::RDS::DBInstance
    Properties:
      EnablePerformanceInsights: true
      PerformanceInsightsKMSKeyId: "something"


```




### Related Links


- [https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.htm](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.htm)


