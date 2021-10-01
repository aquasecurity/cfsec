package vpc

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
)

func Test_SSM_SecretUseCustomerKey_FailureExamples(t *testing.T) {
	expectedCode := "aws-ssm-secret-use-customer-key"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_VPC_SecretUseCustomerKey_SuccessExamples(t *testing.T) {
	expectedCode := "aws-ssm-secret-use-customer-key"
	test.RunPassingExamplesTest(t, expectedCode)
}
