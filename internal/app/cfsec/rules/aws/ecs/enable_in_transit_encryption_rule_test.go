package ecs

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/ecs"
)

func Test_CheckEnableInTransitEncryption_FailureExamples(t *testing.T) {
	expectedCode := ecs.CheckEnableInTransitEncryption.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableInTransitEncryption_PassedExamples(t *testing.T) {
	expectedCode := ecs.CheckEnableInTransitEncryption.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}

