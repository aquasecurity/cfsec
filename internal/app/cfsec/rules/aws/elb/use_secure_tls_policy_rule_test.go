package elb

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/elb"
)

func Test_CheckUseSecureTlsPolicy_FailureExamples(t *testing.T) {
	expectedCode := elb.CheckUseSecureTlsPolicy.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckUseSecureTlsPolicy_PassedExamples(t *testing.T) {
	expectedCode := elb.CheckUseSecureTlsPolicy.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
