---
title: RDS encryption has not been enabled at a DB Instance level.
shortcode: encrypt-instance-storage-data
summary: RDS encryption has not been enabled at a DB Instance level. 
permalink: /docs/rds/encrypt-instance-storage-data/
---

### Explanation

Encryption should be enabled for an RDS Database instances. 

When enabling encryption by setting the kms_key_id.

### Possible Impact
Data can be read from RDS instances if compromised

### Suggested Resolution
Enable encryption for RDS instances


### Insecure Example

The following example will fail the AVD-AWS-0080 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example of rds sgr
Resources:
  Instance:
    Type: AWS::RDS::DBInstance
    Properties:
      StorageEncrypted: false


```



### Secure Example

The following example will pass the AVD-AWS-0080 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of rds sgr
Resources:
  Instance:
    Type: AWS::RDS::DBInstance
    Properties:
      StorageEncrypted: true
      KmsKeyId: "something"


```




### Related Links


- [https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html)


