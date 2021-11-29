---
title: Root and user volumes on Workspaces should be encrypted
shortcode: enable-disk-encryption
summary: Root and user volumes on Workspaces should be encrypted 
permalink: /docs/workspaces/enable-disk-encryption/
---

### Explanation

Workspace volumes for both user and root should be encrypted to protect the data stored on them.

### Possible Impact
Data can be freely read if compromised

### Suggested Resolution
Root and user volume encryption should be enabled


### Insecure Example

The following example will fail the AVD-AWS-0109 check.

```yaml
---
Resources:
  BadExample:
    Type: AWS::WorkSpaces::Workspace
    Properties: 
      RootVolumeEncryptionEnabled: false
      UserVolumeEncryptionEnabled: false
      UserName: "admin"

```



### Secure Example

The following example will pass the AVD-AWS-0109 check.

```yaml
---
Resources:
  GoodExample:
    Type: AWS::WorkSpaces::Workspace
    Properties:
      RootVolumeEncryptionEnabled: true
      UserVolumeEncryptionEnabled: true
      UserName: "admin"

```




### Related Links


- [https://docs.aws.amazon.com/workspaces/latest/adminguide/encrypt-workspaces.html](https://docs.aws.amazon.com/workspaces/latest/adminguide/encrypt-workspaces.html)


