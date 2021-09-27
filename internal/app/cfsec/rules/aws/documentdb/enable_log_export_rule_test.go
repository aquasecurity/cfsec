package documentdb

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/documentdb"
)

func Test_CheckEnableLogExport_FailureExamples(t *testing.T) {
	expectedCode := documentdb.CheckEnableLogExport.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableLogExport_PassedExamples(t *testing.T) {
	expectedCode := documentdb.CheckEnableLogExport.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}

