package sam

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/sam"

	"testing"
)

func Test_CheckEnableHttpApiAccessLogging_FailureExamples(t *testing.T) {
	expectedCode := sam.CheckEnableApiAccessLogging.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableHttpApiAccessLogging_PassedExamples(t *testing.T) {
	expectedCode := sam.CheckEnableHttpApiAccessLogging.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
