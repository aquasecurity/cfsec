package ebs

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/ebs"
)

func Test_CheckEncryptionCustomerKey_FailureExamples(t *testing.T) {
	expectedCode := ebs.CheckEncryptionCustomerKey.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEncryptionCustomerKey_PassedExamples(t *testing.T) {
	expectedCode := ebs.CheckEncryptionCustomerKey.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
