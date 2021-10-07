package vpc

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/vpc"
)

func Test_CheckNoPublicIngressSgr_FailureExamples(t *testing.T) {
	expectedCode := vpc.CheckNoPublicIngressSgr.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckNoPublicIngressSgr_SuccessExamples(t *testing.T) {
	expectedCode := vpc.CheckNoPublicIngressSgr.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
