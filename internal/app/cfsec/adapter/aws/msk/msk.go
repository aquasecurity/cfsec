package msk

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/msk"
	"github.com/aquasecurity/defsec/types"
)

func Adapt(cfFile parser.FileContext) msk.MSK {
	return msk.MSK{
		Clusters: getClusters(cfFile),
	}
}

func getClusters(ctx parser.FileContext) (clusters []msk.Cluster) {
	for _, clusterResource := range ctx.GetResourceByType("AWS::MSK::Cluster") {

		var cluster msk.Cluster

		if brokerProp := clusterResource.GetProperty("EncryptionInfo.EncryptionInTransit.ClientBroker"); brokerProp.IsString() {
			cluster.EncryptionInTransit.ClientBroker = brokerProp.AsStringValue()
		} else {
			cluster.EncryptionInTransit.ClientBroker = types.StringDefault("TLS", clusterResource.Metadata())
		}

		if logsProp := clusterResource.GetProperty("LoggingInfo.BrokerLogs"); logsProp.IsNotNil() {
			if cloudwatchProp := logsProp.GetProperty("CloudWatchLogs"); cloudwatchProp.IsNotNil() {
				if enableProp := cloudwatchProp.GetProperty("Enabled"); enableProp.IsBool() {
					cluster.Logging.Broker.Cloudwatch.Enabled = enableProp.AsBoolValue()
				} else {
					cluster.Logging.Broker.Cloudwatch.Enabled = types.BoolDefault(false, cloudwatchProp.Metadata())
				}
			} else {
				cluster.Logging.Broker.Cloudwatch.Enabled = types.BoolDefault(false, logsProp.Metadata())
			}

			if firehoseProp := logsProp.GetProperty("Firehose"); firehoseProp.IsNotNil() {
				if enableProp := firehoseProp.GetProperty("Enabled"); enableProp.IsBool() {
					cluster.Logging.Broker.Firehose.Enabled = enableProp.AsBoolValue()
				} else {
					cluster.Logging.Broker.Firehose.Enabled = types.BoolDefault(false, firehoseProp.Metadata())
				}
			} else {
				cluster.Logging.Broker.Firehose.Enabled = types.BoolDefault(false, logsProp.Metadata())
			}

			if s3Prop := logsProp.GetProperty("S3"); s3Prop.IsNotNil() {
				if enableProp := s3Prop.GetProperty("Enabled"); enableProp.IsBool() {
					cluster.Logging.Broker.S3.Enabled = enableProp.AsBoolValue()
				} else {
					cluster.Logging.Broker.S3.Enabled = types.BoolDefault(false, s3Prop.Metadata())
				}
			} else {
				cluster.Logging.Broker.S3.Enabled = types.BoolDefault(false, logsProp.Metadata())
			}

		} else {
			cluster.Logging.Broker.Cloudwatch.Enabled = types.BoolDefault(false, clusterResource.Metadata())
			cluster.Logging.Broker.Firehose.Enabled = types.BoolDefault(false, clusterResource.Metadata())
			cluster.Logging.Broker.S3.Enabled = types.BoolDefault(false, clusterResource.Metadata())
		}

		clusters = append(clusters, cluster)
	}
	return clusters
}
