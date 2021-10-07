package redshift

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/redshift"
)

func Test_CheckUsesVPC_FailureExamples(t *testing.T) {
	expectedCode := redshift.CheckUsesVPC.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckUsesVPC_SuccessExamples(t *testing.T) {
	expectedCode := redshift.CheckUsesVPC.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
