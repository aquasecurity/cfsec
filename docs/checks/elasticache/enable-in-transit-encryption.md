---
title: Elasticache Replication Group uses unencrypted traffic.
shortcode: enable-in-transit-encryption
summary: Elasticache Replication Group uses unencrypted traffic. 
permalink: /docs/elasticache/enable-in-transit-encryption/
---

### Explanation

Traffic flowing between Elasticache replication nodes should be encrypted to ensure sensitive data is kept private.

### Possible Impact
In transit data in the Replication Group could be read if intercepted

### Suggested Resolution
Enable in transit encryption for replication group


### Insecure Example

The following example will fail the AVD-AWS-0051 check.

```yaml
---
Resources:
  BadExample:
    Type: 'AWS::ElastiCache::ReplicationGroup'
    Properties:
      AutomaticFailoverEnabled: true    
      CacheNodeType: cache.r3.large
      CacheSubnetGroupName: !Ref CacheSubnetGroup
      Engine: redis
      EngineVersion: '3.2'
      NumNodeGroups: '2'
      ReplicasPerNodeGroup: '3'
      Port: 6379
      PreferredMaintenanceWindow: 'sun:05:00-sun:09:00'
      ReplicationGroupDescription: A sample replication group
      SecurityGroupIds:
      - !Ref ReplicationGroupSG
      SnapshotRetentionLimit: 5
      SnapshotWindow: '10:00-12:00'

```



### Secure Example

The following example will pass the AVD-AWS-0051 check.

```yaml
---
Resources:
  GoodExample:
    Type: 'AWS::ElastiCache::ReplicationGroup'
    Properties:
      AutomaticFailoverEnabled: true    
      CacheNodeType: cache.r3.large
      CacheSubnetGroupName: !Ref CacheSubnetGroup
      Engine: redis
      EngineVersion: '3.2'
      NumNodeGroups: '2'
      ReplicasPerNodeGroup: '3'
      Port: 6379
      PreferredMaintenanceWindow: 'sun:05:00-sun:09:00'
      ReplicationGroupDescription: A sample replication group
      SecurityGroupIds:
      - !Ref ReplicationGroupSG
      SnapshotRetentionLimit: 5
      SnapshotWindow: '10:00-12:00'   
      TransitEncryptionEnabled: true

```




### Related Links


- [https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/in-transit-encryption.html](https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/in-transit-encryption.html)


