package rds

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/rds"
)

func Test_CheckNoPublicDbAccess_FailureExamples(t *testing.T) {
	expectedCode := rds.CheckNoPublicDbAccess.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckNoPublicDbAccess_SuccessExamples(t *testing.T) {
	expectedCode := rds.CheckNoPublicDbAccess.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
