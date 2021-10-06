package elasticache

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/elasticache"
	"github.com/aquasecurity/defsec/types"
)

func getClusterGroups(ctx parser.FileContext) (clusters []elasticache.Cluster) {

	clusterResources := ctx.GetResourceByType("AWS::ElastiCache::CacheCluster")

	for _, r := range clusterResources {
		cluster := elasticache.Cluster{
			Engine:                 getEngine(r),
			NodeType:               getNodeType(r),
			SnapshotRetentionLimit: getSnapshotRetentionLimit(r),
		}

		clusters =  append(clusters, cluster)
	}

	return clusters
}

func getSnapshotRetentionLimit(r *parser.Resource) types.IntValue {
	snapshotLimitProp := r.GetProperty("SnapshotRetentionLimit")

	if snapshotLimitProp.IsNotInt() {
		return r.IntDefault(0)
	}

	return snapshotLimitProp.AsIntValue()

}

func getNodeType(r *parser.Resource) types.StringValue {
	nodeProp := r.GetProperty("CacheNodeType")

	if nodeProp.IsNotString() {
		return r.StringDefault("")
	}

	return nodeProp.AsStringValue()
}

func getEngine(r *parser.Resource) types.StringValue {
	engineProp := r.GetProperty("Engine")

	if engineProp.IsNotString() {
		return r.StringDefault("")
	}

	return engineProp.AsStringValue()
}
