package cloudtrail

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/cloudtrail"
	"testing"
)

func Test_CheckEnableAllRegions_FailureExamples(t *testing.T) {
	expectedCode := cloudtrail.CheckEnableAllRegions.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableAllRegions_PassedExamples(t *testing.T) {
	expectedCode := cloudtrail.CheckEnableAllRegions.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
