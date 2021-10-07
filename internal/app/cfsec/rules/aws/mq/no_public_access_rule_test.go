package rds

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/mq"
)

func Test_CheckNoPublicAccess_FailureExamples(t *testing.T) {
	expectedCode := mq.CheckNoPublicAccess.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckNoPublicAccess_SuccessExamples(t *testing.T) {
	expectedCode := mq.CheckNoPublicAccess.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
