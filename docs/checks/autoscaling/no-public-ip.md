---
title: Launch configuration should not have a public IP address.
shortcode: no-public-ip
summary: Launch configuration should not have a public IP address. 
permalink: /docs/autoscaling/no-public-ip/
---

### Explanation

You should limit the provision of public IP addresses for resources. Resources should not be exposed on the public internet, but should have access limited to consumers required for the function of your application.

### Possible Impact
The instance or configuration is publicly accessible

### Suggested Resolution
Set the instance to not be publicly accessible


### Insecure Example

The following example will fail the AVD-AWS-0009 check.

```yaml
---
Resources:
  BadExample:
    Properties:
      AssociatePublicIpAddress: true
      ImageId: ami-123456
      InstanceType: t2.small
    Type: AWS::AutoScaling::LaunchConfiguration

```



### Secure Example

The following example will pass the AVD-AWS-0009 check.

```yaml
---
Resources:
  GoodExample:
    Properties:
      ImageId: ami-123456
      InstanceType: t2.small
    Type: AWS::AutoScaling::LaunchConfiguration

```




### Related Links


- [https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html)


