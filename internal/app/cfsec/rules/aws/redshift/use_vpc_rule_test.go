package redshift

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
)

func Test_Redshift_UseVPC_FailureExamples(t *testing.T) {
	expectedCode := "aws-redshift-use-vpc"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_Redshift_UseVPC_SuccessExamples(t *testing.T) {
	expectedCode := "aws-redshift-use-vpc"
	test.RunPassingExamplesTest(t, expectedCode)
}
