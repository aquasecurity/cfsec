package rds

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
)

func Test_RDS_EnablePI_FailureExamples(t *testing.T) {
	expectedCode := "aws-rds-enable-performance-insights"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_RDS_EnablePI_SuccessExamples(t *testing.T) {
	expectedCode := "aws-rds-enable-performance-insights"
	test.RunPassingExamplesTest(t, expectedCode)
}
