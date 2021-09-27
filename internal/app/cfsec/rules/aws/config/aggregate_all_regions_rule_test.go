package config

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/config"

	"testing"
)

func Test_CheckAggregateAllRegions_FailureExamples(t *testing.T) {
	expectedCode := config.CheckAggregateAllRegions.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckAggregateAllRegions_PassedExamples(t *testing.T) {
	expectedCode := config.CheckAggregateAllRegions.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}

