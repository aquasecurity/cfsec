package sam

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/sam"

	"testing"
)

func Test_CheckEnableStateMachineTracing_FailureExamples(t *testing.T) {
	expectedCode := sam.CheckEnableStateMachineTracing.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableStateMachineTracing_PassedExamples(t *testing.T) {
	expectedCode := sam.CheckEnableStateMachineTracing.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
