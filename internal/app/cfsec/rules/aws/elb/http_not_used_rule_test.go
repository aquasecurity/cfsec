package elb

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/elb"
)
func Test_CheckHttpNotUsed_FailureExamples(t *testing.T) {
	expectedCode := elb.CheckHttpNotUsed.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckHttpNotUsed_PassedExamples(t *testing.T) {
	expectedCode := elb.CheckHttpNotUsed.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}

