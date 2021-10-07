package vpc

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/sqs"
)

func Test_CheckNoWildcardsInPolicyDocuments_FailureExamples(t *testing.T) {
	expectedCode := sqs.CheckNoWildcardsInPolicyDocuments.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckNoWildcardsInPolicyDocuments_SuccessExamples(t *testing.T) {
	expectedCode := sqs.CheckNoWildcardsInPolicyDocuments.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
