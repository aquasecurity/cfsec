package sns

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/sns"
	"github.com/aquasecurity/defsec/types"
)

func Adapt(cfFile parser.FileContext) sns.SNS {
	return sns.SNS{
		Topics: getTopics(cfFile),
	}
}

func getTopics(ctx parser.FileContext) (topics []sns.Topic) {
	for _, topicResource := range ctx.GetResourceByType("AWS::SNS::Topic") {
		var topic sns.Topic
		topic.Metadata = topicResource.Metadata()
		if kmsProp := topicResource.GetProperty("KmsMasterKeyId"); kmsProp.IsString() {
			topic.Encryption.KMSKeyID = kmsProp.AsStringValue()
		} else {
			topic.Encryption.KMSKeyID = types.StringDefault("", topicResource.Metadata())
		}
		topics = append(topics, topic)
	}
	return topics
}
