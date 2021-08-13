package apigateway

// generator-locked
import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/result"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rule"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/severity"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/resource"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS061",
		Service:   "api-gateway",
		ShortCode: "enable-access-logging",
		Documentation: rule.RuleDocumentation{
			BadExample: []string{`
resource "aws_apigatewayv2_stage" "bad_example" {
  api_id = aws_apigatewayv2_api.example.id
  name   = "example-stage"
}

resource "aws_api_gateway_stage" "bad_example" {
  deployment_id = aws_api_gateway_deployment.example.id
  rest_api_id   = aws_api_gateway_rest_api.example.id
  stage_name    = "example"
}
`},
			GoodExample: []string{`
resource "aws_apigatewayv2_stage" "good_example" {
  api_id = aws_apigatewayv2_api.example.id
  name   = "example-stage"

  access_log_settings {
    destination_arn = ""
    format          = ""
  }
}

resource "aws_api_gateway_stage" "good_example" {
  deployment_id = aws_api_gateway_deployment.example.id
  rest_api_id   = aws_api_gateway_rest_api.example.id
  stage_name    = "example"

  access_log_settings {
    destination_arn = ""
    format          = ""
  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/apigatewayv2_stage#access_log_settings",
				"https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html",
			},
		},

		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_apigatewayv2_stage", "aws_api_gateway_stage"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
