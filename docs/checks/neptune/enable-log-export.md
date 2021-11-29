---
title: Neptune logs export should be enabled
shortcode: enable-log-export
summary: Neptune logs export should be enabled 
permalink: /docs/neptune/enable-log-export/
---

### Explanation

Neptune does not have auditing by default. To ensure that you are able to accurately audit the usage of your Neptune instance you should enable export logs.

### Possible Impact
Limited visibility of audit trail for changes to Neptune

### Suggested Resolution
Enable export logs


### Insecure Example

The following example will fail the AVD-AWS-0075 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example
Resources:
  Cluster:
    Type: AWS::Neptune::DBCluster
    Properties:
      EnableCloudwatchLogsExports:
        - debug


```



### Secure Example

The following example will pass the AVD-AWS-0075 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example
Resources:
  Cluster:
    Type: AWS::Neptune::DBCluster
    Properties:
      EnableCloudwatchLogsExports:
        - audit



```




### Related Links


- [https://docs.aws.amazon.com/neptune/latest/userguide/auditing.html](https://docs.aws.amazon.com/neptune/latest/userguide/auditing.html)


