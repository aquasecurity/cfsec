package sam

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/sam"

	"testing"
)

func Test_CheckEnableApiTracingFailureExamples(t *testing.T) {
	expectedCode := sam.CheckEnableApiTracing.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableApiTracing_PassedExamples(t *testing.T) {
	expectedCode := sam.CheckEnableApiTracing.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
