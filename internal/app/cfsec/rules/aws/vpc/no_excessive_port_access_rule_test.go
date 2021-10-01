package vpc

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
)

func Test_VPC_ExcessivePortAccess_FailureExamples(t *testing.T) {
	expectedCode := "aws-vpc-no-excessive-port-access"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_VPC_ExcessivePortAccess_SuccessExamples(t *testing.T) {
	expectedCode := "aws-vpc-no-excessive-port-access"
	test.RunPassingExamplesTest(t, expectedCode)
}
