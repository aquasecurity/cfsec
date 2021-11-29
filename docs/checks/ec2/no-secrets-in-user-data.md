---
title: User data for EC2 instances must not contain sensitive AWS keys
shortcode: no-secrets-in-user-data
summary: User data for EC2 instances must not contain sensitive AWS keys 
permalink: /docs/ec2/no-secrets-in-user-data/
---

### Explanation

EC2 instance data is used to pass start up information into the EC2 instance. This userdata must not contain access key credentials. Instead use an IAM Instance Profile assigned to the instance to grant access to other AWS Services.

### Possible Impact
User data is visible through the AWS Management console

### Suggested Resolution
Remove sensitive data from the EC2 instance user-data


### Insecure Example

The following example will fail the AVD-AWS-0029 check.

```yaml
---
Resources:
  BadExample:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: "ami-79fd7eee"
      KeyName: "testkey"
      UserData: export DATABASE_PASSWORD=password1234
      BlockDeviceMappings:
        - DeviceName: "/dev/sdm"
          Ebs:
            VolumeType: "io1"
            Iops: "200"
            DeleteOnTermination: "false"
            VolumeSize: "20"
        - DeviceName: "/dev/sdk"


```



### Secure Example

The following example will pass the AVD-AWS-0029 check.

```yaml
---
Resources:
  GoodExample:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: "ami-79fd7eee"
      KeyName: "testkey"
      UserData: export SSM_PATH=/database/creds
      BlockDeviceMappings:
        - DeviceName: "/dev/sdm"
          Ebs:
            VolumeType: "io1"
            Iops: "200"
            DeleteOnTermination: "false"
            VolumeSize: "20"
        - DeviceName: "/dev/sdk"


```




### Related Links


- [https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-add-user-data.html](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-add-user-data.html)


