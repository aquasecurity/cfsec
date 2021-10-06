package rds

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
)

func Test_RDS_NoPublicAccess_FailureExamples(t *testing.T) {
	expectedCode := "aws-rds-no-public-db-access"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_RDS_NoPublicAccess_SuccessExamples(t *testing.T) {
	expectedCode := "aws-rds-no-public-db-access"
	test.RunPassingExamplesTest(t, expectedCode)
}
