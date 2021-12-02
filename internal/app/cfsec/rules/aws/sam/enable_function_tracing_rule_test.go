package sam

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/sam"

	"testing"
)

func Test_CheckEnableFunctionTracing_FailureExamples(t *testing.T) {
	expectedCode := sam.CheckEnableFunctionTracing.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableFunctionTracing_PassedExamples(t *testing.T) {
	expectedCode := sam.CheckEnableFunctionTracing.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
