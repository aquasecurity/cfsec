package rds

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/msk"
)

func Test_CheckEnableLogging_FailureExamples(t *testing.T) {
	expectedCode := msk.CheckEnableLogging.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableLogging_SuccessExamples(t *testing.T) {
	expectedCode := msk.CheckEnableLogging.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
