package mq

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/mq"
	"github.com/aquasecurity/defsec/types"
)

func Adapt(cfFile parser.FileContext) mq.MQ {
	return mq.MQ{
		Brokers: getBrokers(cfFile),
	}
}

func getBrokers(ctx parser.FileContext) (brokers []mq.Broker) {
	for _, brokerResource := range ctx.GetResourceByType("AWS::AmazonMQ::Broker") {

		var broker mq.Broker
		broker.Metadata = brokerResource.Metadata()

		if publicProp := brokerResource.GetProperty("PubliclyAccessible"); publicProp.IsBool() {
			broker.PublicAccess = publicProp.AsBoolValue()
		} else {
			broker.PublicAccess = types.BoolDefault(false, brokerResource.Metadata())
		}

		if logsProp := brokerResource.GetProperty("Logs"); logsProp.IsNotNil() {
			if auditProp := logsProp.GetProperty("Audit"); auditProp.IsBool() {
				broker.Logging.Audit = auditProp.AsBoolValue()
			} else {
				broker.Logging.Audit = types.BoolDefault(false, logsProp.Metadata())
			}
			if generalProp := logsProp.GetProperty("General"); generalProp.IsBool() {
				broker.Logging.General = generalProp.AsBoolValue()
			} else {
				broker.Logging.General = types.BoolDefault(false, logsProp.Metadata())
			}
		} else {
			broker.Logging.Audit = types.BoolDefault(false, brokerResource.Metadata())
			broker.Logging.General = types.BoolDefault(false, brokerResource.Metadata())
		}

		brokers = append(brokers, broker)
	}
	return brokers
}
