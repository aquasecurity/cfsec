package apigateway

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/apigateway"
	"github.com/aquasecurity/defsec/types"
)

func getApis(cfFile parser.FileContext) (apis []apigateway.API) {


	apiResources := cfFile.GetResourceByType(apiGatewayType)
	for _, apiRes := range apiResources {
		api := apigateway.API{
			Metadata: apiRes.Metadata(),
			Stages: getStages(apiRes.ID(), cfFile),
		}
		apis = append(apis, api)
	}

	return apis
}

func getStages(apiId string, cfFile parser.FileContext) []apigateway.Stage {
	var apiStages []apigateway.Stage

	stageResources := cfFile.GetResourceByType("AWS::ApiGatewayV2::Stage")
	for _, stageRes := range stageResources {
		stageApiId := getApiID(stageRes)
		if stageApiId.Value() != apiId {
			continue
		}

		s := apigateway.Stage{
			Metadata:  stageRes.Metadata(),
			Name:          getStageName(stageRes),
			AccessLogging: getAccessLogging(stageRes),
		}
		apiStages = append(apiStages, s)
	}

	return apiStages
}

func getApiID(res *parser.Resource) types.StringValue {
	apiIDProp := res.GetProperty("ApiId")
	if apiIDProp == nil {
		return types.StringDefault("", res.Metadata())
	}
	return apiIDProp.AsStringValue()
}

func getStageName(res *parser.Resource) types.StringValue {
	stageNameProp := res.GetProperty("StageName")
	if stageNameProp == nil {
		return types.StringDefault("", res.Metadata())
	}
	return stageNameProp.AsStringValue()
}

func getAccessLogging(r *parser.Resource) apigateway.AccessLogging {

	loggingProp := r.GetProperty("AccessLogSettings")
	if loggingProp.IsNil() {
		return apigateway.AccessLogging{
			Metadata: r.Metadata(),
		}
	}

	destinationProp := r.GetProperty("AccessLogSettings.DestinationArn")

	if destinationProp.IsNil() {
		return apigateway.AccessLogging{
			Metadata: loggingProp.Metadata(),
			CloudwatchLogGroupARN: types.StringDefault("", r.Metadata()),
		}
	}
	return apigateway.AccessLogging{
		CloudwatchLogGroupARN: destinationProp.AsStringValue(),
	}
}
