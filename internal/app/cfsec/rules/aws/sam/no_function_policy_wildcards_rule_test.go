package sam

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/sam"

	"testing"
)

func Test_CheckNoFunctionPolicyWildcards_FailureExamples(t *testing.T) {
	expectedCode := sam.CheckNoFunctionPolicyWildcards.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckNoFunctionPolicyWildcards_PassedExamples(t *testing.T) {
	expectedCode := sam.CheckNoFunctionPolicyWildcards.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
