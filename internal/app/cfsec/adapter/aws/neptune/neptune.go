package neptune

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/neptune"
	"github.com/aquasecurity/defsec/types"
)

func Adapt(cfFile parser.FileContext) neptune.Neptune {
	return neptune.Neptune{
		Clusters: getClusters(cfFile),
	}
}

func getClusters(ctx parser.FileContext) (clusters []neptune.Cluster) {
	for _, clusterResource := range ctx.GetResourceByType("AWS::Neptune::DBCluster") {
		var cluster neptune.Cluster
		if encryptedProp := clusterResource.GetProperty("StorageEncrypted"); encryptedProp.IsBool() {
			cluster.StorageEncrypted = encryptedProp.AsBoolValue()
		} else {
			cluster.StorageEncrypted = types.BoolDefault(false, clusterResource.Metadata())
		}
		if keyProp := clusterResource.GetProperty("KmsKeyId"); keyProp.IsString() {
			cluster.KMSKeyID = keyProp.AsStringValue()
		} else {
			cluster.KMSKeyID = types.StringDefault("", clusterResource.Metadata())
		}

		if logsProp := clusterResource.GetProperty("EnableCloudwatchLogsExports"); logsProp.IsList() {
			var ok bool
			for _, log := range logsProp.AsList() {
				if log.IsString() && log.AsString() == "audit" {
					cluster.Logging.Audit = types.Bool(true, log.Metadata())
					ok = true
					break
				}
			}
			if !ok {
				cluster.Logging.Audit = types.Bool(false, logsProp.Metadata())
			}
		} else {
			cluster.Logging.Audit = types.BoolDefault(false, clusterResource.Metadata())
		}

		clusters = append(clusters, cluster)
	}
	return clusters
}
