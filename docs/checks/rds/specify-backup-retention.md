---
title: RDS Cluster and RDS instance should have backup retention longer than default 1 day
shortcode: specify-backup-retention
summary: RDS Cluster and RDS instance should have backup retention longer than default 1 day 
permalink: /docs/rds/specify-backup-retention/
---

### Explanation

RDS backup retention for clusters defaults to 1 day, this may not be enough to identify and respond to an issue. Backup retention periods should be set to a period that is a balance on cost and limiting risk.

### Possible Impact
Potential loss of data and short opportunity for recovery

### Suggested Resolution
Explicitly set the retention period to greater than the default


### Insecure Example

The following example will fail the AVD-AWS-0077 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example
Resources:
  Queue:
    Type: AWS::RDS::DBInstance
    Properties:


```



### Secure Example

The following example will pass the AVD-AWS-0077 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example
Resources:
  Queue:
    Type: AWS::RDS::DBInstance
    Properties:
      BackupRetentionPeriod: 30


```




### Related Links


- [https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html#USER_WorkingWithAutomatedBackups.BackupRetention](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html#USER_WorkingWithAutomatedBackups.BackupRetention)


