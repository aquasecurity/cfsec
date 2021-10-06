package redshift

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
)

func Test_Redshift_EncryptionCustomerKey_FailureExamples(t *testing.T) {
	expectedCode := "aws-redshift-encryption-customer-key"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_Redshift_EncryptionCustomerKey_SuccessExamples(t *testing.T) {
	expectedCode := "aws-redshift-encryption-customer-key"
	test.RunPassingExamplesTest(t, expectedCode)
}
