package rds

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/rds"
)

func Test_CheckEncryptClusterStorageData_FailureExamples(t *testing.T) {
	expectedCode := rds.CheckEncryptClusterStorageData.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEncryptClusterStorageData_SuccessExamples(t *testing.T) {
	expectedCode := rds.CheckEncryptClusterStorageData.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
