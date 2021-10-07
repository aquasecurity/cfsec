package rds

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/neptune"
)

func Test_CheckEnableLogExport_FailureExamples(t *testing.T) {
	expectedCode := neptune.CheckEnableLogExport.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableLogExport_SuccessExamples(t *testing.T) {
	expectedCode := neptune.CheckEnableLogExport.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
