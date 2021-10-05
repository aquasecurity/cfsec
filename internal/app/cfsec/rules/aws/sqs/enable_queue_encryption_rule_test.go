package vpc

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
)

func Test_SQS_EnableQueueEncryption_FailureExamples(t *testing.T) {
	expectedCode := "aws-sqs-enable-queue-encryption"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_SQS_EnableQueueEncryption_SuccessExamples(t *testing.T) {
	expectedCode := "aws-sqs-enable-queue-encryption"
	test.RunPassingExamplesTest(t, expectedCode)
}
