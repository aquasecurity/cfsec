package ecs

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/ecs"
)

func Test_CheckNoPlaintextSecrets_FailureExamples(t *testing.T) {
	expectedCode := ecs.CheckNoPlaintextSecrets.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckNoPlaintextSecrets_PassedExamples(t *testing.T) {
	expectedCode := ecs.CheckNoPlaintextSecrets.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
