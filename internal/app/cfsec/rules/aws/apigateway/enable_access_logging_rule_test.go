package apigateway

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"testing"
)

func Test_EnableAccessLogging_FailureExamples(t *testing.T) {
	expectedCode := "aws-api-gateway-enable-access-logging"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_EnableAccessLogging_PassedExamples(t *testing.T) {
	expectedCode := "aws-api-gateway-enable-access-logging"
	test.RunPassingExamplesTest(t, expectedCode)
}
