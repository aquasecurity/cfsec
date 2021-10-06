package documentdb

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/documentdb"
)

func Test_CheckEnableStorageEncryption_FailureExamples(t *testing.T) {
	expectedCode := documentdb.CheckEnableStorageEncryption.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableStorageEncryption_PassedExamples(t *testing.T) {
	expectedCode := documentdb.CheckEnableStorageEncryption.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
