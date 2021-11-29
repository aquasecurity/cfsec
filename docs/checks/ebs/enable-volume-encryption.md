---
title: EBS volumes must be encrypted
shortcode: enable-volume-encryption
summary: EBS volumes must be encrypted 
permalink: /docs/ebs/enable-volume-encryption/
---

### Explanation

By enabling encryption on EBS volumes you protect the volume, the disk I/O and any derived snapshots from compromise if intercepted.

### Possible Impact
Unencrypted sensitive data is vulnerable to compromise.

### Suggested Resolution
Enable encryption of EBS volumes


### Insecure Example

The following example will fail the AVD-AWS-0026 check.

```yaml
---
Resources:
  BadExample:
    Type: AWS::EC2::Volume
    Properties:
      Size: 100
      AvailabilityZone: !GetAtt Ec2Instance.AvailabilityZone
    DeletionPolicy: Snapshot

```



### Secure Example

The following example will pass the AVD-AWS-0026 check.

```yaml
---
Resources:
  GoodExample:
    Type: AWS::EC2::Volume
    Properties: 
      Size: 100
      Encrypted: true
      KmsKeyId: "alias/volumeEncrypt"
    DeletionPolicy: Snapshot

```




### Related Links


- [https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html)


