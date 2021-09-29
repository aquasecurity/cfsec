package vpc

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
)

func Test_EnableAccessLogging_FailureExamples(t *testing.T) {
	expectedCode := "aws-vpc-add-description-to-security-group"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_EnableAccessLogging_PassedExamples(t *testing.T) {
	expectedCode := "aws-vpc-add-description-to-security-group"
	test.RunPassingExamplesTest(t, expectedCode)
}
