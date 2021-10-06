package elb

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/elb"
)
func Test_CheckDropInvalidHeaders_FailureExamples(t *testing.T) {
	expectedCode := elb.CheckDropInvalidHeaders.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckDropInvalidHeaders_PassedExamples(t *testing.T) {
	expectedCode := elb.CheckDropInvalidHeaders.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}

