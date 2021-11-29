---
title: ECS Task Definitions with EFS volumes should use in-transit encryption
shortcode: enable-in-transit-encryption
summary: ECS Task Definitions with EFS volumes should use in-transit encryption 
permalink: /docs/ecs/enable-in-transit-encryption/
---

### Explanation

ECS task definitions that have volumes using EFS configuration should explicitly enable in transit encryption to prevent the risk of data loss due to interception.

### Possible Impact
Intercepted traffic to and from EFS may lead to data loss

### Suggested Resolution
Enable in transit encryption when using efs


### Insecure Example

The following example will fail the AVD-AWS-0035 check.

```yaml
---
Resources:
  BadExample:
    Type: 'AWS::ECS::Cluster'
    Properties:
      ClusterName: MyCluster
      ClusterSettings:
        - Name: containerInsights
          Value: enabled
  BadTask:
    Type: AWS::ECS::TaskDefinition
    Properties:
      Family: "CFSec scan"
      Cpu: 512
      Memory: 1024
      NetworkMode: awsvpc
      RequiresCompatibilities:
        - FARGATE
        - EC2
      ContainerDefinitions:
        - Name: cfsec
          Image: cfsec/cfsec:latest
          MountPoints:
            - SourceVolume: src
              ContainerPath: /src
          LogConfiguration:
            LogDriver: awslogs
            Options:
              awslogs-group: "cfsec-logs"
              awslogs-region: !Ref AWS::Region
              awslogs-stream-prefix: "cfsec"
      Volumes:
        - Name: jenkins-home
          EFSVolumeConfiguration:
            FilesystemId: "fs1"
            TransitEncryption: DISABLED
```



### Secure Example

The following example will pass the AVD-AWS-0035 check.

```yaml
---
Resources:
  GoodExample:
    Type: 'AWS::ECS::Cluster'
    Properties:
      ClusterName: MyCluster
      ClusterSettings:
        - Name: containerInsights
          Value: enabled
  GoodTask:
    Type: AWS::ECS::TaskDefinition
    Properties:
      Family: "CFSec scan"
      Cpu: 512
      Memory: 1024
      NetworkMode: awsvpc
      RequiresCompatibilities:
        - FARGATE
        - EC2
      ContainerDefinitions:
        - Name: cfsec
          Image: cfsec/cfsec:latest
          MountPoints:
            - SourceVolume: src
              ContainerPath: /src
          LogConfiguration:
            LogDriver: awslogs
            Options:
              awslogs-group: "cfsec-logs"
              awslogs-region: !Ref AWS::Region
              awslogs-stream-prefix: "cfsec"
      Volumes:
        - Name: jenkins-home
          EFSVolumeConfiguration:
            FilesystemId: "fs1"
            TransitEncryption: ENABLED

```




### Related Links


- [https://docs.aws.amazon.com/AmazonECS/latest/userguide/efs-volumes.html](https://docs.aws.amazon.com/AmazonECS/latest/userguide/efs-volumes.html)

- [https://docs.aws.amazon.com/efs/latest/ug/encryption-in-transit.html](https://docs.aws.amazon.com/efs/latest/ug/encryption-in-transit.html)


