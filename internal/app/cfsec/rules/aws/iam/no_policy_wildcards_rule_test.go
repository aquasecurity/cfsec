package vpc

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/iam"
)

func Test_CheckNoPolicyWildcards_FailureExamples(t *testing.T) {
	expectedCode := iam.CheckNoPolicyWildcards.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckNoPolicyWildcards_SuccessExamples(t *testing.T) {
	expectedCode := iam.CheckNoPolicyWildcards.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
