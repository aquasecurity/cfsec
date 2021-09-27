package documentdb

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/workspaces"
)

func Test_CheckEnableDiskEncryption_FailureExamples(t *testing.T) {
	expectedCode := workspaces.CheckEnableDiskEncryption.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableDiskEncryption_PassedExamples(t *testing.T) {
	expectedCode := workspaces.CheckEnableDiskEncryption.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
