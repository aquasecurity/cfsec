package rds

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
)

func Test_RDS_EncryptInstance_FailureExamples(t *testing.T) {
	expectedCode := "aws-rds-encrypt-instance-storage-data"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_RDS_EncryptInstance_SuccessExamples(t *testing.T) {
	expectedCode := "aws-rds-encrypt-instance-storage-data"
	test.RunPassingExamplesTest(t, expectedCode)
}
