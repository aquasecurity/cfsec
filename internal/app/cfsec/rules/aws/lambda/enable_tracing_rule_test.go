package lambda

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/lambda"
)

func Test_CheckEnableTracing_FailureExamples(t *testing.T) {
	expectedCode := lambda.CheckEnableTracing.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableTracing_SuccessExamples(t *testing.T) {
	expectedCode := lambda.CheckEnableTracing.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
