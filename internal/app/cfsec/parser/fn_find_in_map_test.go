package parser

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"testing"
)

func Test_resolve_find_in_map_value(t *testing.T) {

	source := `---
Parameters:
  Environment: 
    Type: String
    Default: production
Mappings:
  CacheNodeTypes:
    production:
      NodeType: ami-0e9a69a55428bef3b
    test:
      NodeType: ami-0548a8b7c1afc24ee
    dev:
      NodeType: ami-0b19db5a228d1055f
Resources:
	ElasticacheSecurityGroup:
	  Type: 'AWS::EC2::SecurityGroup'
	  Properties:
	    GroupDescription: Elasticache Security Group
	    SecurityGroupIngress:
	      - IpProtocol: tcp
	        FromPort: 11211
	        ToPort: 11211
	        SourceSecurityGroupName: !Ref InstanceSecurityGroup
	ElasticacheCluster:
	  Type: 'AWS::ElastiCache::CacheCluster'
	  Properties:    
	    Engine: memcached
	    CacheNodeType: !FindInMap [ CacheNodeTypes, !Ref environment, NodeType ]
	    NumCacheNodes: '1'
	    VpcSecurityGroupIds:
	      - !GetAtt 
	        - ElasticacheSecurityGroup
	        - GroupId
`
	contexts := createTestFileContexts(t, source)
	require.Len(t, contexts, 1)

	ctx := contexts[0]

	testRes := ctx.GetResourceByLogicalID("CacheNodeType")
	assert.NotNil(t, testRes)

}
