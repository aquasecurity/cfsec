---
title: DocumentDB storage must be encrypted
shortcode: enable-storage-encryption
summary: DocumentDB storage must be encrypted 
permalink: /docs/documentdb/enable-storage-encryption/
---

### Explanation

Encryption of the underlying storage used by DocumentDB ensures that if their is compromise of the disks, the data is still protected.

### Possible Impact
Unencrypted sensitive data is vulnerable to compromise.

### Suggested Resolution
Enable storage encryption


### Insecure Example

The following example will fail the AVD-AWS-0021 check.

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

The following example will pass the AVD-AWS-0021 check.

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
      StorageEncrypted: true
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


- [https://docs.aws.amazon.com/documentdb/latest/developerguide/encryption-at-rest.html](https://docs.aws.amazon.com/documentdb/latest/developerguide/encryption-at-rest.html)


