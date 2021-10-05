package vpc

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
)

func Test_SNS_EnableTopicEncryption_FailureExamples(t *testing.T) {
	expectedCode := "aws-sns-enable-topic-encryption"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_SNS_EnableTopicEncryption_SuccessExamples(t *testing.T) {
	expectedCode := "aws-sns-enable-topic-encryption"
	test.RunPassingExamplesTest(t, expectedCode)
}
