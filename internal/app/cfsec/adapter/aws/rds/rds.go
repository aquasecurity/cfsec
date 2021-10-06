package rds

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/rds"
	"github.com/aquasecurity/defsec/types"
)

func Adapt(cfFile parser.FileContext) rds.RDS {
	clusters, orphans := getClustersAndInstances(cfFile)
	return rds.RDS{
		Instances: orphans,
		Clusters:  clusters,
		Classic:   getClassic(cfFile),
	}
}

func getClustersAndInstances(ctx parser.FileContext) (clusters []rds.Cluster,
	orphans []rds.Instance) {

	clusterMap := getClusters(ctx)

	for _, instanceResource := range ctx.GetResourceByType("AWS::RDS::DBInstance") {

		var instance rds.Instance
		instance.Metadata = instanceResource.Metadata()

		if backupProp := instanceResource.GetProperty("BackupRetentionPeriod"); backupProp.IsInt() {
			instance.BackupRetentionPeriodDays = backupProp.AsIntValue()
		} else {
			instance.BackupRetentionPeriodDays = types.IntDefault(1, instanceResource.Metadata())
		}

		if replicaProp := instanceResource.GetProperty("SourceDBInstanceIdentifier"); replicaProp.IsString() {
			instance.ReplicationSourceARN = replicaProp.AsStringValue()
		} else {
			instance.ReplicationSourceARN = types.StringDefault("", instanceResource.Metadata())
		}

		if piProp := instanceResource.GetProperty("EnablePerformanceInsights"); piProp.IsBool() {
			instance.PerformanceInsights.Enabled = piProp.AsBoolValue()
		} else {
			instance.PerformanceInsights.Enabled = types.BoolDefault(false, instanceResource.Metadata())
		}

		if insightsKeyProp := instanceResource.GetProperty("PerformanceInsightsKMSKeyId"); insightsKeyProp.IsString() {
			instance.PerformanceInsights.KMSKeyID = insightsKeyProp.AsStringValue()
		} else {
			instance.PerformanceInsights.KMSKeyID = types.StringDefault("", instanceResource.Metadata())
		}

		if publicProp := instanceResource.GetProperty("PubliclyAccessible"); publicProp.IsBool() {
			instance.PublicAccess = publicProp.AsBoolValue()
		} else {
			instance.PublicAccess = types.BoolDefault(true, instanceResource.Metadata())
		}

		if encryptedProp := instanceResource.GetProperty("StorageEncrypted"); encryptedProp.IsBool() {
			instance.Encryption.EncryptStorage = encryptedProp.AsBoolValue()
		} else {
			instance.Encryption.EncryptStorage = types.BoolDefault(false, instanceResource.Metadata())
		}

		if keyProp := instanceResource.GetProperty("KmsKeyId"); keyProp.IsString() {
			instance.Encryption.KMSKeyID = keyProp.AsStringValue()
		} else {
			instance.Encryption.KMSKeyID = types.StringDefault("", instanceResource.Metadata())
		}

		if clusterID := instanceResource.GetProperty("DBClusterIdentifier"); clusterID.IsString() {
			var found bool
			for key, cluster := range clusterMap {
				if key == clusterID.AsString() {
					cluster.Instances = append(cluster.Instances, rds.ClusterInstance(instance))
					clusterMap[key] = cluster
					found = true
					break
				}
			}
			if found {
				continue
			}
		}

		orphans = append(orphans, instance)
	}

	for _, cluster := range clusterMap {
		clusters = append(clusters, cluster)
	}

	return clusters, orphans
}

func getClusters(ctx parser.FileContext) (clusters map[string]rds.Cluster) {
	clusters = make(map[string]rds.Cluster)
	for _, clusterResource := range ctx.GetResourceByType("AWS::RDS::DBCluster") {
		var cluster rds.Cluster
		cluster.Metadata = clusterResource.Metadata()
		if backupProp := clusterResource.GetProperty("BackupRetentionPeriod"); backupProp.IsInt() {
			cluster.BackupRetentionPeriodDays = backupProp.AsIntValue()
		} else {
			cluster.BackupRetentionPeriodDays = types.IntDefault(1, clusterResource.Metadata())
		}

		if replicaProp := clusterResource.GetProperty("SourceDBInstanceIdentifier"); replicaProp.IsString() {
			cluster.ReplicationSourceARN = replicaProp.AsStringValue()
		} else {
			cluster.ReplicationSourceARN = types.StringDefault("", clusterResource.Metadata())
		}

		if piProp := clusterResource.GetProperty("EnablePerformanceInsights"); piProp.IsBool() {
			cluster.PerformanceInsights.Enabled = piProp.AsBoolValue()
		} else {
			cluster.PerformanceInsights.Enabled = types.BoolDefault(false, clusterResource.Metadata())
		}

		if insightsKeyProp := clusterResource.GetProperty("PerformanceInsightsKMSKeyId"); insightsKeyProp.IsString() {
			cluster.PerformanceInsights.KMSKeyID = insightsKeyProp.AsStringValue()
		} else {
			cluster.PerformanceInsights.KMSKeyID = types.StringDefault("", clusterResource.Metadata())
		}

		if encryptedProp := clusterResource.GetProperty("StorageEncrypted"); encryptedProp.IsBool() {
			cluster.Encryption.EncryptStorage = encryptedProp.AsBoolValue()
		} else {
			cluster.Encryption.EncryptStorage = types.BoolDefault(false, clusterResource.Metadata())
		}

		if keyProp := clusterResource.GetProperty("KmsKeyId"); keyProp.IsString() {
			cluster.Encryption.KMSKeyID = keyProp.AsStringValue()
		} else {
			cluster.Encryption.KMSKeyID = types.StringDefault("", clusterResource.Metadata())
		}

		clusters[clusterResource.ID()] = cluster
	}
	return clusters
}

func getClassic(ctx parser.FileContext) rds.Classic {
	return rds.Classic{
		DBSecurityGroups: getClassicSecurityGroups(ctx),
	}
}

func getClassicSecurityGroups(ctx parser.FileContext) (groups []rds.DBSecurityGroup) {
	for _, dbsgResource := range ctx.GetResourceByType("AWS::RDS::DBSecurityGroup") {
		var group rds.DBSecurityGroup
		group.Metadata = dbsgResource.Metadata()
		groups = append(groups, group)
	}
	return groups
}
