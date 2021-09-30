package ec2

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/ec2"
)

func Test_CheckNoSecretsInUserData_FailureExamples(t *testing.T) {
	expectedCode := ec2.CheckNoSecretsInUserData.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckNoSecretsInUserData_PassedExamples(t *testing.T) {
	expectedCode := ec2.CheckNoSecretsInUserData.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}

