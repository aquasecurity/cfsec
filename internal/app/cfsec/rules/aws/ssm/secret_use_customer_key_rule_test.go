package vpc

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/ssm"
)

func Test_CheckSecretUseCustomerKey_FailureExamples(t *testing.T) {
	expectedCode := ssm.CheckSecretUseCustomerKey.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckSecretUseCustomerKey_SuccessExamples(t *testing.T) {
	expectedCode := ssm.CheckSecretUseCustomerKey.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
