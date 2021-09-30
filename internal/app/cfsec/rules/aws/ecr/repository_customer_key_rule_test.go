package ecr

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/ecr"
)

func Test_CheckRepositoryCustomerKey_FailureExamples(t *testing.T) {
	expectedCode := ecr.CheckRepositoryCustomerKey.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckRepositoryCustomerKey_PassedExamples(t *testing.T) {
	expectedCode := ecr.CheckRepositoryCustomerKey.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}

