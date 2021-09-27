package autoscaling

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"testing"
)

func Test_AutoscalingCheckEnableAtRestEncryption_FailureExamples(t *testing.T) {
	expectedCode := "aws-autoscaling-enable-at-rest-encryption"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_AutoscalingCheckEnableAtRestEncryption_PassedExamples(t *testing.T) {
	expectedCode := "aws-autoscaling-enable-at-rest-encryption"
	test.RunPassingExamplesTest(t, expectedCode)
}
