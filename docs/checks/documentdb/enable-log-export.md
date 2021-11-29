---
title: DocumentDB logs export should be enabled
shortcode: enable-log-export
summary: DocumentDB logs export should be enabled 
permalink: /docs/documentdb/enable-log-export/
---

### Explanation

Document DB does not have auditing by default. To ensure that you are able to accurately audit the usage of your DocumentDB cluster you should enable export logs.

### Possible Impact
Limited visibility of audit trail for changes to the DocumentDB

### Suggested Resolution
Enable export logs


### Insecure Example

The following example will fail the AVD-AWS-0020 check.

```yaml
---
 Resources:
  BadExample:
    Type: "AWS::DocDB::DBCluster"
    Properties:
      BackupRetentionPeriod: 8
      DBClusterIdentifier: sample-cluster
      DBClusterParameterGroupName: default.docdb3.6
  BadInstanceExample:
    Type: "AWS::DocDB::DBInstance"
    Properties:
      AutoMinorVersionUpgrade: true
      AvailabilityZone: us-east-1c
      DBClusterIdentifier: sample-cluster
      DBInstanceClass: db.r5.large
      DBInstanceIdentifier: sample-cluster-instance-0
      PreferredMaintenanceWindow: 'sat:06:54-sat:07:24'

```



### Secure Example

The following example will pass the AVD-AWS-0020 check.

```yaml
---
Resources:
  GoodExample:
    Type: "AWS::DocDB::DBCluster"
    Properties:
      BackupRetentionPeriod : 8
      DBClusterIdentifier : "sample-cluster"
      DBClusterParameterGroupName : "default.docdb3.6"
      KmsKeyId : "your-kms-key-id"
      EnableCloudwatchLogsExports:
      - audit
      - profiler
  InstanceInstanceExample:
    Type: "AWS::DocDB::DBInstance"
    Properties:
      AutoMinorVersionUpgrade: true
      AvailabilityZone: "us-east-1c"
      DBClusterIdentifier: "sample-cluster"
      DBInstanceClass: "db.r5.large"
      DBInstanceIdentifier: "sample-cluster-instance-0"
      PreferredMaintenanceWindow: "sat:06:54-sat:07:24"

```




### Related Links


- [https://docs.aws.amazon.com/documentdb/latest/developerguide/event-auditing.html](https://docs.aws.amazon.com/documentdb/latest/developerguide/event-auditing.html)


