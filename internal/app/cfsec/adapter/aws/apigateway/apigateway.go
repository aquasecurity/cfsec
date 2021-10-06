package apigateway

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/apigateway"
)

const (
	apiGatewayType      = "AWS::ApiGatewayV2::Api"
	apiGatewayStageType = "AWS::ApiGatewayV2::Stage"
)

func Adapt(cfFile parser.FileContext) apigateway.APIGateway {
	return apigateway.APIGateway{
		APIs: getApis(cfFile),
	}
}
