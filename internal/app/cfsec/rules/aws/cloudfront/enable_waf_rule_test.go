package cloudfront

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/cloudfront"

	"testing"
)

func Test_CheckEnableWaf_FailureExamples(t *testing.T) {
	expectedCode := cloudfront.CheckEnableWaf.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableWaf_PassedExamples(t *testing.T) {
	expectedCode := cloudfront.CheckEnableWaf.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
