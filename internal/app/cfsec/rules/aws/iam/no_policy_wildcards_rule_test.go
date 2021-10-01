package vpc

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
)

func Test_IAM_NoPolicyWildcards_FailureExamples(t *testing.T) {
	expectedCode := "aws-iam-no-policy-wildcards"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_IAM_NoPolicyWildcards_SuccessExamples(t *testing.T) {
	expectedCode := "aws-iam-no-policy-wildcards"
	test.RunPassingExamplesTest(t, expectedCode)
}
