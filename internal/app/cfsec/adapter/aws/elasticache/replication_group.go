package elasticache

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/elasticache"
	"github.com/aquasecurity/defsec/types"
)

func getReplicationGroups(ctx parser.FileContext) (replicationGroups []elasticache.ReplicationGroup) {

	replicationGroupResources := ctx.GetResourceByType("AWS::ElastiCache::ReplicationGroup")

	for _, r := range replicationGroupResources {
		replicationGroup := elasticache.ReplicationGroup{
			TransitEncryptionEnabled: isEncryptionEnabled(r),
		}

		replicationGroups = append(replicationGroups, replicationGroup)
	}

	return replicationGroups
}

func isEncryptionEnabled(r *parser.Resource) types.BoolValue {

	transitEncryptionProp := r.GetProperty("TransitEncryptionEnabled")

	if transitEncryptionProp.IsNotBool() {
		return r.BoolDefault(false)
	}

	return transitEncryptionProp.AsBoolValue()
}
