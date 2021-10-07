package rds

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/mq"
)

func Test_CheckEnableGeneralLogging_FailureExamples(t *testing.T) {
	expectedCode := mq.CheckEnableGeneralLogging.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableGeneralLogging_SuccessExamples(t *testing.T) {
	expectedCode := mq.CheckEnableGeneralLogging.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
