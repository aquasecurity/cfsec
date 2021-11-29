---
title: EFS Encryption has not been enabled
shortcode: enable-at-rest-encryption
summary: EFS Encryption has not been enabled 
permalink: /docs/efs/enable-at-rest-encryption/
---

### Explanation

If your organization is subject to corporate or regulatory policies that require encryption of data and metadata at rest, we recommend creating a file system that is encrypted at rest, and mounting your file system using encryption of data in transit.

### Possible Impact
Data can be read from the EFS if compromised

### Suggested Resolution
Enable encryption for EFS


### Insecure Example

The following example will fail the AVD-AWS-0037 check.

```yaml
---
Resources:
  BadExample:
    Type: AWS::EFS::FileSystem
    Properties:
      BackupPolicy:
        Status: ENABLED
      LifecyclePolicies:
        - TransitionToIA: AFTER_60_DAYS
      PerformanceMode: generalPurpose
      Encrypted: false
      ThroughputMode: bursting

```



### Secure Example

The following example will pass the AVD-AWS-0037 check.

```yaml
---
Resources:
  GoodExample:
    Type: AWS::EFS::FileSystem
    Properties:
      BackupPolicy:
        Status: ENABLED
      LifecyclePolicies:
        - TransitionToIA: AFTER_60_DAYS
      PerformanceMode: generalPurpose
      Encrypted: true
      ThroughputMode: bursting

```




### Related Links


- [https://docs.aws.amazon.com/efs/latest/ug/encryption.html](https://docs.aws.amazon.com/efs/latest/ug/encryption.html)


