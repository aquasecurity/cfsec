package rds

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
)

func Test_MSK_Logs_FailureExamples(t *testing.T) {
	expectedCode := "aws-msk-enable-logging"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_MSK_Logs_SuccessExamples(t *testing.T) {
	expectedCode := "aws-msk-enable-logging"
	test.RunPassingExamplesTest(t, expectedCode)
}
