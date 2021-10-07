package vpc

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/vpc"
)

func Test_CheckNoPublicIngress_FailureExamples(t *testing.T) {
	expectedCode := vpc.CheckNoPublicIngress.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckNoPublicIngress_SuccessExamples(t *testing.T) {
	expectedCode := vpc.CheckNoPublicIngress.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
