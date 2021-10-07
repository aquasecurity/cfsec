package vpc

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/vpc"
)

func Test_CheckNoPublicEgressSgr_FailureExamples(t *testing.T) {
	expectedCode := vpc.CheckNoPublicEgressSgr.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckNoPublicEgressSgr_SuccessExamples(t *testing.T) {
	expectedCode := vpc.CheckNoPublicEgressSgr.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
