package rds

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
)

func Test_RDS_NoClassicResources_FailureExamples(t *testing.T) {
	expectedCode := "aws-rds-no-classic-resources"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_RDS_NoClassicResources_SuccessExamples(t *testing.T) {
	expectedCode := "aws-rds-no-classic-resources"
	test.RunPassingExamplesTest(t, expectedCode)
}
