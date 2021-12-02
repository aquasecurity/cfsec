package sam

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/sam"
)

func Test_CheckEnableTableEncryption_FailureExamples(t *testing.T) {
	expectedCode := sam.CheckEnableTableEncryption.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableTableEncryption_PassedExamples(t *testing.T) {
	expectedCode := sam.CheckEnableTableEncryption.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
