package sam

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/sam"

	"testing"
)

func Test_CheckNoStateMachinePolicyWildcards_FailureExamples(t *testing.T) {
	expectedCode := sam.CheckNoStateMachinePolicyWildcards.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckNoStateMachinePolicyWildcards_PassedExamples(t *testing.T) {
	expectedCode := sam.CheckNoStateMachinePolicyWildcards.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
