---
title: Redis cluster should have backup retention turned on
shortcode: enable-backup-retention
summary: Redis cluster should have backup retention turned on 
permalink: /docs/elasticache/enable-backup-retention/
---

### Explanation

Redis clusters should have a snapshot retention time to ensure that they are backed up and can be restored if required.

### Possible Impact
Without backups of the redis cluster recovery is made difficult

### Suggested Resolution
Configure snapshot retention for redis cluster


### Insecure Example

The following example will fail the AVD-AWS-0050 check.

```yaml
---
Resources:
  BadExample:
    Type: AWS::ElastiCache::CacheCluster
    Properties:
      AZMode: cross-az
      CacheNodeType: cache.m3.medium
      Engine: redis
      NumCacheNodes: '3'
      PreferredAvailabilityZones:
        - us-west-2a
        - us-west-2a
        - us-west-2b 

```



### Secure Example

The following example will pass the AVD-AWS-0050 check.

```yaml
---
Resources:
  GoodExample:
    Type: AWS::ElastiCache::CacheCluster
    Properties:
      AZMode: cross-az
      CacheNodeType: cache.m3.medium
      Engine: redis
      NumCacheNodes: '3'
      SnapshotRetentionLimit: 7
      PreferredAvailabilityZones:
        - us-west-2a
        - us-west-2a
        - us-west-2b 

```




### Related Links


- [https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/backups-automatic.html](https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/backups-automatic.html)


