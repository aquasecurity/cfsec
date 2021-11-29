---
title: Neptune storage must be encrypted at rest
shortcode: enable-storage-encryption
summary: Neptune storage must be encrypted at rest 
permalink: /docs/neptune/enable-storage-encryption/
---

### Explanation

Encryption of Neptune storage ensures that if their is compromise of the disks, the data is still protected.

### Possible Impact
Unencrypted sensitive data is vulnerable to compromise.

### Suggested Resolution
Enable encryption of Neptune storage


### Insecure Example

The following example will fail the AVD-AWS-0076 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bad example
Resources:
  Cluster:
    Type: AWS::Neptune::DBCluster
    Properties:
      StorageEncrypted: false


```



### Secure Example

The following example will pass the AVD-AWS-0076 check.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example
Resources:
  Cluster:
    Type: AWS::Neptune::DBCluster
    Properties:
      StorageEncrypted: true
      KmsKeyId: "something"


```




### Related Links


- [https://docs.aws.amazon.com/neptune/latest/userguide/encrypt.html](https://docs.aws.amazon.com/neptune/latest/userguide/encrypt.html)


