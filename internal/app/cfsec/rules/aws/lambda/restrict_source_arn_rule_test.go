package lambda

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/lambda"
)

func Test_CheckRestrictSourceArn_FailureExamples(t *testing.T) {
	expectedCode := lambda.CheckRestrictSourceArn.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckRestrictSourceArn_SuccessExamples(t *testing.T) {
	expectedCode := lambda.CheckRestrictSourceArn.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
