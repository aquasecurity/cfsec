---
title: Task definition defines sensitive environment variable(s).
shortcode: no-plaintext-secrets
summary: Task definition defines sensitive environment variable(s). 
permalink: /docs/ecs/no-plaintext-secrets/
---

### Explanation

You should not make secrets available to a user in plaintext in any scenario. Secrets can instead be pulled from a secure secret storage system by the service requiring them.

### Possible Impact
Sensitive data could be exposed in the AWS Management Console

### Suggested Resolution
Use secrets for the task definition


### Insecure Example

The following example will fail the AVD-AWS-0036 check.

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
          Environment: 
          - Name: AWS_ACCESS_KEY_ID 
            Value: AIPA8YOHGIS58IBFDU3E
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

The following example will pass the AVD-AWS-0036 check.

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


- [https://docs.aws.amazon.com/systems-manager/latest/userguide/integration-ps-secretsmanager.html](https://docs.aws.amazon.com/systems-manager/latest/userguide/integration-ps-secretsmanager.html)

- [https://www.vaultproject.io/](https://www.vaultproject.io/)


