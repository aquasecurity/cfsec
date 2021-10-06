package rds

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
)

func Test_Neptune_EncryptCluster_FailureExamples(t *testing.T) {
	expectedCode := "aws-neptune-enable-storage-encryption"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_Neptune_EncryptCluster_SuccessExamples(t *testing.T) {
	expectedCode := "aws-neptune-enable-storage-encryption"
	test.RunPassingExamplesTest(t, expectedCode)
}
