package rds

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/mq"
)

func Test_CheckEnableAuditLogging_FailureExamples(t *testing.T) {
	expectedCode := mq.CheckEnableAuditLogging.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableAuditLogging_SuccessExamples(t *testing.T) {
	expectedCode := mq.CheckEnableAuditLogging.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
