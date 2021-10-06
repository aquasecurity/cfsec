package documentdb

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/documentdb"
	"github.com/aquasecurity/defsec/types"
)

func getClusters(ctx parser.FileContext) (clusters []documentdb.Cluster) {

	clusterResources := ctx.GetResourceByType("AWS::DocDB::DBCluster")

	for _, r := range clusterResources {
		cluster := documentdb.Cluster{
			Metadata:          r.Metadata(),
			Identifier:        getIdentifier(r),
			EnabledLogExports: getLogExports(r),
			StorageEncrypted:  isStorageEncrypted(r),
			KMSKeyID:          getKmsKeyId(r),
		}

		updateInstancesOnCluster(&cluster, ctx)

		clusters = append(clusters, cluster)
	}
	return clusters
}

func updateInstancesOnCluster(cluster *documentdb.Cluster, ctx parser.FileContext) {

	instanceResources := ctx.GetResourceByType("AWS::DocDB::DBInstance")

	for _, r := range instanceResources {
		clusterIdentifier := getIdentifier(r)
		if clusterIdentifier == cluster.Identifier {
			cluster.Instances = append(cluster.Instances, documentdb.Instance{
				Metadata: r.Metadata(),
				KMSKeyID: cluster.KMSKeyID,
			})
		}
	}
}

func getKmsKeyId(r *parser.Resource) types.StringValue {
	kmsIdProp := r.GetProperty("KmsKeyId")
	if kmsIdProp.IsNil() || kmsIdProp.IsNotString() {
		return types.StringDefault("", r.Metadata())
	}
	return kmsIdProp.AsStringValue()
}

func getLogExports(r *parser.Resource) (logExports []types.StringValue) {

	exportsList := r.GetProperty("EnableCloudwatchLogsExports")

	if exportsList.IsNil() || exportsList.IsNotList() {
		return logExports
	}

	for _, export := range exportsList.AsList() {
		logExports = append(logExports, export.AsStringValue())
	}
	return logExports
}

func isStorageEncrypted(r *parser.Resource) types.BoolValue {
	encryptedProp := r.GetProperty("StorageEncrypted")
	if encryptedProp.IsNil() || encryptedProp.IsNotBool() {
		return types.BoolDefault(false, r.Metadata())
	}
	return encryptedProp.AsBoolValue()
}

func getIdentifier(r *parser.Resource) types.StringValue {
	identifierProp := r.GetProperty("DBClusterIdentifier")
	if identifierProp.IsNil() {
		return types.StringDefault("", r.Metadata())
	}
	return identifierProp.AsStringValue()
}
