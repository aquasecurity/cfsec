package cloudfront

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/cloudfront"

	"testing"
)

func Test_CheckEnforceHttps_FailureExamples(t *testing.T) {
	expectedCode := cloudfront.CheckEnforceHttps.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnforceHttps_PassedExamples(t *testing.T) {
	expectedCode := cloudfront.CheckEnforceHttps.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
