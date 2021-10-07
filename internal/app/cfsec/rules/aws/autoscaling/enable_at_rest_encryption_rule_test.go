package autoscaling

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/autoscaling"

	"testing"
)

func Test_CheckEnableAtRestEncryption_FailureExamples(t *testing.T) {
	expectedCode := autoscaling.CheckEnableAtRestEncryption.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableAtRestEncryption_PassedExamples(t *testing.T) {
	expectedCode := autoscaling.CheckEnableAtRestEncryption.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
