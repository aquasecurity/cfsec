package rds

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
)

func Test_RDS_BackupRetention_FailureExamples(t *testing.T) {
	expectedCode := "aws-rds-specify-backup-retention"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_RDS_BackupRetention_SuccessExamples(t *testing.T) {
	expectedCode := "aws-rds-specify-backup-retention"
	test.RunPassingExamplesTest(t, expectedCode)
}
