---
title: Launch configuration with unencrypted block device.
shortcode: enable-at-rest-encryption
summary: Launch configuration with unencrypted block device. 
permalink: /docs/autoscaling/enable-at-rest-encryption/
---

### Explanation

Block devices should be encrypted to ensure sensitive data is held securely at rest.

### Possible Impact
The block device could be compromised and read from

### Suggested Resolution
Turn on encryption for all block devices


### Insecure Example

The following example will fail the AVD-AWS-0008 check.

```yaml
---
Resources:
  BadExample:
    Properties:
      BlockDeviceMappings:
        - DeviceName: root
          Ebs:
            Encrypted: true
        - DeviceName: data
          Ebs:
            Encrypted: false
      ImageId: ami-123456
      InstanceType: t2.small
    Type: AWS::AutoScaling::LaunchConfiguration

```



### Secure Example

The following example will pass the AVD-AWS-0008 check.

```yaml
---
Resources:
  GoodExample:
    Properties:
      BlockDeviceMappings:
        - DeviceName: root
          Ebs:
            Encrypted: true
      ImageId: ami-123456
      InstanceType: t2.small
    Type: AWS::AutoScaling::LaunchConfiguration

```




### Related Links


- [https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/RootDeviceStorage.html](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/RootDeviceStorage.html)


