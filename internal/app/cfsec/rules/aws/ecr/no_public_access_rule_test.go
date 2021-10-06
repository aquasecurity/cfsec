package ecr

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/ecr"
)

func Test_CheckNoPublicAccess_FailureExamples(t *testing.T) {
	expectedCode := ecr.CheckNoPublicAccess.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckNoPublicAccess_PassedExamples(t *testing.T) {
	expectedCode := ecr.CheckNoPublicAccess.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
