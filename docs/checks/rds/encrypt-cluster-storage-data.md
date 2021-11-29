---
title: There is no encryption specified or encryption is disabled on the RDS Cluster.
shortcode: encrypt-cluster-storage-data
summary: There is no encryption specified or encryption is disabled on the RDS Cluster. 
permalink: /docs/rds/encrypt-cluster-storage-data/
---

### Explanation

Encryption should be enabled for an RDS Aurora cluster. 

When enabling encryption by setting the kms_key_id, the storage_encrypted must also be set to true.

### Possible Impact
Data can be read from the RDS cluster if it is compromised

### Suggested Resolution
Enable encryption for RDS clusters


### Insecure Example

The following example will fail the AVD-AWS-0079 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of rds sgr
Resources:
  Cluster:
    Type: AWS::RDS::DBCluster
    Properties:
      StorageEncrypted: false


```



### Secure Example

The following example will pass the AVD-AWS-0079 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of rds sgr
Resources:
  Cluster:
    Type: AWS::RDS::DBCluster
    Properties:
      StorageEncrypted: true
      KmsKeyId: "something"


```




### Related Links


- [https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html)


