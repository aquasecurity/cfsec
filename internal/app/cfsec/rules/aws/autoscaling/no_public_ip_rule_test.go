package autoscaling

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"testing"
)

func Test_AutoScalingCheckNoPublicIp_FailureExamples(t *testing.T) {
	expectedCode := "aws-autoscaling-no-public-ip"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_AutoScalingCheckNoPublicIp_PassedExamples(t *testing.T) {
	expectedCode := "aws-autoscaling-no-public-ip"
	test.RunPassingExamplesTest(t, expectedCode)
}
