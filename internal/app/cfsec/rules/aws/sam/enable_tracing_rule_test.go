package sam

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	sam "github.com/aquasecurity/defsec/rules/aws/sam"

	"testing"
)

func Test_CheckEnableTracing_FailureExamples(t *testing.T) {
	expectedCode := sam.CheckEnableTracing.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableTracing_PassedExamples(t *testing.T) {
	expectedCode := sam.CheckEnableTracing.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
