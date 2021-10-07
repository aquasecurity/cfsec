package vpc

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/sqs"
)

func Test_CheckEnableQueueEncryption_FailureExamples(t *testing.T) {
	expectedCode := sqs.CheckEnableQueueEncryption.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableQueueEncryption_SuccessExamples(t *testing.T) {
	expectedCode := sqs.CheckEnableQueueEncryption.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
