package rds

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
)

func Test_MQ_GeneralLogs_FailureExamples(t *testing.T) {
	expectedCode := "aws-mq-enable-audit-logging"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_MQ_GeneralLogs_SuccessExamples(t *testing.T) {
	expectedCode := "aws-mq-enable-audit-logging"
	test.RunPassingExamplesTest(t, expectedCode)
}
