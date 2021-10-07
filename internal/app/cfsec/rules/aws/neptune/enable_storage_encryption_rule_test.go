package rds

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/neptune"
)

func Test_CheckEnableStorageEncryption_FailureExamples(t *testing.T) {
	expectedCode := neptune.CheckEnableStorageEncryption.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableStorageEncryption_SuccessExamples(t *testing.T) {
	expectedCode := neptune.CheckEnableStorageEncryption.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
