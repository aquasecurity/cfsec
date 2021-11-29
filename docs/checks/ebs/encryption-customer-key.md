---
title: EBS volume encryption should use Customer Managed Keys
shortcode: encryption-customer-key
summary: EBS volume encryption should use Customer Managed Keys 
permalink: /docs/ebs/encryption-customer-key/
---

### Explanation

Encryption using AWS keys provides protection for your EBS volume. To increase control of the encryption and manage factors like rotation use customer managed keys.

### Possible Impact
Using AWS managed keys does not allow for fine grained control

### Suggested Resolution
Enable encryption using customer managed keys


### Insecure Example

The following example will fail the AVD-AWS-0027 check.

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

The following example will pass the AVD-AWS-0027 check.

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


