package dynamodb

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/dynamodb"
	"github.com/aquasecurity/defsec/types"
)

func getClusters(file parser.FileContext) (clusters []dynamodb.DAXCluster) {

	clusterResources := file.GetResourceByType("AWS::DAX::Cluster")

	for _, r := range clusterResources {
		cluster := dynamodb.DAXCluster{
			Metadata:             r.Metadata(),
			ServerSideEncryption: dynamodb.ServerSideEncryption{
				Enabled: isEnabled(r),
			},
			PointInTimeRecovery:  nil,
		}

		clusters = append(clusters, cluster)
	}

	return clusters
}

func isEnabled(r *parser.Resource) types.BoolValue {

	sseEnabled := r.GetProperty("SSESpecification.SSEEnabled")
	if sseEnabled.IsNil() || sseEnabled.IsNotBool() {
		return types.BoolDefault(false, r.Metadata())
	}
	return sseEnabled.AsBoolValue()
}