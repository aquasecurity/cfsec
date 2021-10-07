package rds

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/rds"
)

func Test_CheckEnablePerformanceInsights_FailureExamples(t *testing.T) {
	expectedCode := rds.CheckEnablePerformanceInsights.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnablePerformanceInsights_SuccessExamples(t *testing.T) {
	expectedCode := rds.CheckEnablePerformanceInsights.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
