package cloudfront

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/cloudfront"

	"testing"
)

func Test_CheckEnableLogging_FailureExamples(t *testing.T) {
	expectedCode := cloudfront.CheckEnableLogging.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableLogging_PassedExamples(t *testing.T) {
	expectedCode := cloudfront.CheckEnableLogging.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
