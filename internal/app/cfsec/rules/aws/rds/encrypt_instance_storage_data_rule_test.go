package rds

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/rds"
)

func Test_CheckEncryptInstanceStorageData_FailureExamples(t *testing.T) {
	expectedCode := rds.CheckEncryptInstanceStorageData.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEncryptInstanceStorageData_SuccessExamples(t *testing.T) {
	expectedCode := rds.CheckEncryptInstanceStorageData.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
