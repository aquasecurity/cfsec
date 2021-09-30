package ecs

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/ecs"
)

func Test_CheckEnableContainerInsight_FailureExamples(t *testing.T) {
	expectedCode := ecs.CheckEnableContainerInsight.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableContainerInsight_PassedExamples(t *testing.T) {
	expectedCode := ecs.CheckEnableContainerInsight.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}

