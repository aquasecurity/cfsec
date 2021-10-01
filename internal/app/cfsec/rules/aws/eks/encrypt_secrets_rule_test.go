package eks

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/eks"
)
func Test_CheckEncryptSecrets_FailureExamples(t *testing.T) {
	expectedCode := eks.CheckEncryptSecrets.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEncryptSecrets_PassedExamples(t *testing.T) {
	expectedCode := eks.CheckEncryptSecrets.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}

