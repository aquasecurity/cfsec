package rds

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/rds"
)

func Test_CheckNoClassicResources_FailureExamples(t *testing.T) {
	expectedCode := rds.CheckNoClassicResources.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckNoClassicResources_SuccessExamples(t *testing.T) {
	expectedCode := rds.CheckNoClassicResources.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
