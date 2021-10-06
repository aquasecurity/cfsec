package ecr

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/ecr"
)

func Test_CheckEnforceImmutableRepository_FailureExamples(t *testing.T) {
	expectedCode := ecr.CheckEnforceImmutableRepository.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnforceImmutableRepository_PassedExamples(t *testing.T) {
	expectedCode := ecr.CheckEnforceImmutableRepository.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
