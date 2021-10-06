package cloudwatch

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/cloudwatch"
	"github.com/aquasecurity/defsec/types"
)

func getLogGroups(ctx parser.FileContext) (logGroups []cloudwatch.LogGroup) {

	logGroupResources := ctx.GetResourceByType("AWS::Logs::LogGroup")

	for _, r := range logGroupResources {
		group := cloudwatch.LogGroup{
			Name:     getName(r),
			KMSKeyID: getKmsKeyId(r),
		}
		logGroups = append(logGroups, group)
	}

	return logGroups
}

func getKmsKeyId(r *parser.Resource) types.StringValue {
	kmsProp := r.GetProperty("KmsKeyId")
	if kmsProp.IsNil() {
		return types.StringDefault("", r.Metadata())
	}
	return kmsProp.AsStringValue()
}

func getName(r *parser.Resource) types.StringValue {
	logGroupName := r.GetProperty("LogGroupName")
	if logGroupName.IsNil() {
		return types.StringDefault("", r.Metadata())
	}
	return logGroupName.AsStringValue()
}
