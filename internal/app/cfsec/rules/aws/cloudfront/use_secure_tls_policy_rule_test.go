package cloudfront

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/cloudfront"

	"testing"
)

func Test_CheckUseSecureTlsPolicy_FailureExamples(t *testing.T) {
	expectedCode := cloudfront.CheckUseSecureTlsPolicy.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckUseSecureTlsPolicy_PassedExamples(t *testing.T) {
	expectedCode := cloudfront.CheckUseSecureTlsPolicy.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
