package vpc

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
)

func Test_SQS_NoWildcardsInPolicyDocs_FailureExamples(t *testing.T) {
	expectedCode := "aws-sqs-no-wildcards-in-policy-documents"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_SQS_NoWildcardsInPolicyDocs_SuccessExamples(t *testing.T) {
	expectedCode := "aws-sqs-no-wildcards-in-policy-documents"
	test.RunPassingExamplesTest(t, expectedCode)
}
