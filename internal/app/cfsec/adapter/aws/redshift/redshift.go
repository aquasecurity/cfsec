package redshift

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/redshift"
	"github.com/aquasecurity/defsec/types"
)

func Adapt(cfFile parser.FileContext) redshift.Redshift {
	return redshift.Redshift{
		Clusters:       getClusters(cfFile),
		SecurityGroups: getSecurityGroups(cfFile),
	}
}

func getClusters(ctx parser.FileContext) (clusters []redshift.Cluster) {
	for _, clusterResource := range ctx.GetResourceByType("AWS::Redshift::Cluster") {
		var cluster redshift.Cluster
		if subnetProp := clusterResource.GetProperty("ClusterSubnetGroupName"); subnetProp.IsString() {
			cluster.SubnetGroupName = subnetProp.AsStringValue()
		} else {
			cluster.SubnetGroupName = types.StringDefault("", clusterResource.Metadata())
		}
		if encryptedProp := clusterResource.GetProperty("Encrypted"); encryptedProp.IsBool() {
			cluster.Encryption.Enabled = encryptedProp.AsBoolValue()
		} else {
			cluster.Encryption.Enabled = types.BoolDefault(false, clusterResource.Metadata())
		}
		if keyProp := clusterResource.GetProperty("KmsKeyId"); keyProp.IsString() {
			cluster.Encryption.KMSKeyID = keyProp.AsStringValue()
		} else {
			cluster.Encryption.KMSKeyID = types.StringDefault("", clusterResource.Metadata())
		}
		clusters = append(clusters, cluster)
	}
	return clusters
}

func getSecurityGroups(ctx parser.FileContext) (groups []redshift.SecurityGroup) {
	for _, groupResource := range ctx.GetResourceByType("AWS::Redshift::ClusterSecurityGroup") {
		var group redshift.SecurityGroup
		if descProp := groupResource.GetProperty("Description"); descProp.IsString() {
			group.Description = descProp.AsStringValue()
		} else {
			group.Description = types.StringDefault("", groupResource.Metadata())
		}
		groups = append(groups, group)
	}
	return groups
}
