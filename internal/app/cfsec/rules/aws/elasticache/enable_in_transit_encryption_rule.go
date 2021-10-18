package elasticache

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/elasticache"
)

func init() {

	scanner.RegisterCheckRule(rules.Rule{
		BadExample: []string{`---
AWSTemplateFormatVersion: 2010-09-09
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
`},
		GoodExample: []string{`---
AWSTemplateFormatVersion: 2010-09-09
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
`},
		Base: elasticache.CheckEnableInTransitEncryption,
	})
}

var b = `---
AWSTemplateFormatVersion: 2010-09-09
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
      ReplicasPerNodeGroup: '3'Port: 6379
      PreferredMaintenanceWindow: 'sun:05:00-sun:09:00'
      ReplicationGroupDescription: A sample replication group
      SecurityGroupIds:
      - !Ref ReplicationGroupSG
      SnapshotRetentionLimit: 5
      SnapshotWindow: '10:00-12:00'   
      TransitEncryptionEnabled: true
`
