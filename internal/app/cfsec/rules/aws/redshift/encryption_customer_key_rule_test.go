package redshift

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/redshift"
)

func Test_CheckEncryptionCustomerKey_FailureExamples(t *testing.T) {
	expectedCode := redshift.CheckEncryptionCustomerKey.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEncryptionCustomerKey_SuccessExamples(t *testing.T) {
	expectedCode := redshift.CheckEncryptionCustomerKey.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
