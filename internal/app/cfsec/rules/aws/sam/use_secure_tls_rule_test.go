package sam

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	sam "github.com/aquasecurity/defsec/rules/aws/sam"

	"testing"
)

func Test_CheckUseSecureTlsPolicy_FailureExamples(t *testing.T) {
	expectedCode := sam.CheckUseSecureTlsPolicy.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckUseSecureTlsPolicy_PassedExamples(t *testing.T) {
	expectedCode := sam.CheckUseSecureTlsPolicy.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
