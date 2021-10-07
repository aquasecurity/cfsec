package vpc

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/vpc"
)

func Test_CheckNoExcessivePortAccess_FailureExamples(t *testing.T) {
	expectedCode := vpc.CheckNoExcessivePortAccess.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckNoExcessivePortAccess_SuccessExamples(t *testing.T) {
	expectedCode := vpc.CheckNoExcessivePortAccess.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
