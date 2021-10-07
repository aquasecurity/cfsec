package athena

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/athena"

	"testing"
)

func Test_CheckNoEncryptionOverride_FailureExamples(t *testing.T) {
	expectedCode := athena.CheckNoEncryptionOverride.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckNoEncryptionOverride_PassedExamples(t *testing.T) {
	expectedCode := athena.CheckNoEncryptionOverride.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
