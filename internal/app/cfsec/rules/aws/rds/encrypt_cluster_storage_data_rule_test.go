package rds

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
)

func Test_RDS_EncryptCluster_FailureExamples(t *testing.T) {
	expectedCode := "aws-rds-encrypt-cluster-storage-data"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_RDS_EncryptCluster_SuccessExamples(t *testing.T) {
	expectedCode := "aws-rds-encrypt-cluster-storage-data"
	test.RunPassingExamplesTest(t, expectedCode)
}
