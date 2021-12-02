package sam

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/sam"

	"testing"
)

func Test_CheckEnableApiAccessLogging_FailureExamples(t *testing.T) {
	expectedCode := sam.CheckEnableApiAccessLogging.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableApiAccessLogging_PassedExamples(t *testing.T) {
	expectedCode := sam.CheckEnableApiAccessLogging.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
