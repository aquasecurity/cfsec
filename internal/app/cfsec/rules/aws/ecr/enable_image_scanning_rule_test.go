package ecr

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/ecr"
)

func Test_CheckEnableImageScans_FailureExamples(t *testing.T) {
	expectedCode := ecr.CheckEnableImageScans.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableImageScans_PassedExamples(t *testing.T) {
	expectedCode := ecr.CheckEnableImageScans.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}

