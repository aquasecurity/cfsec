package athena

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"testing"
)

func Test_AthenaCheckNoEncryptionOverride_FailureExamples(t *testing.T) {
	expectedCode := "aws-athena-no-encryption-override"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_AthenaCheckNoEncryptionOverride_PassedExamples(t *testing.T) {
	expectedCode := "aws-athena-no-encryption-override"
	test.RunPassingExamplesTest(t, expectedCode)
}
