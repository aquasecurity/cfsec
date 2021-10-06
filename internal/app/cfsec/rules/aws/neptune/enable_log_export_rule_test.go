package rds

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
)

func Test_Neptune_Logs_FailureExamples(t *testing.T) {
	expectedCode := "aws-neptune-enable-log-export"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_Neptune_Logs_SuccessExamples(t *testing.T) {
	expectedCode := "aws-neptune-enable-log-export"
	test.RunPassingExamplesTest(t, expectedCode)
}
