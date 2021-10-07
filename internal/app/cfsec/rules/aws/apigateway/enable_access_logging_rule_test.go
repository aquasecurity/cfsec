package apigateway

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/apigateway"

	"testing"
)

func Test_CheckEnableAccessLogging_FailureExamples(t *testing.T) {
	expectedCode := apigateway.CheckEnableAccessLogging.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableAccessLogging_PassedExamples(t *testing.T) {
	expectedCode := apigateway.CheckEnableAccessLogging.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
