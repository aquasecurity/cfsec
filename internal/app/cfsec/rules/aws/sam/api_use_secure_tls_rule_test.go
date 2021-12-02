package sam

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/sam"

	"testing"
)

func Test_CheckApiUseSecureTlsPolicy_FailureExamples(t *testing.T) {
	expectedCode := sam.CheckApiUseSecureTlsPolicy.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckApiUseSecureTlsPolicy_PassedExamples(t *testing.T) {
	expectedCode := sam.CheckApiUseSecureTlsPolicy.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
