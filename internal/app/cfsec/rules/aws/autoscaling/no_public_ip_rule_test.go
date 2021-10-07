package autoscaling

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/autoscaling"

	"testing"
)

func Test_CheckNoPublicIp_FailureExamples(t *testing.T) {
	expectedCode := autoscaling.CheckNoPublicIp.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckNoPublicIp_PassedExamples(t *testing.T) {
	expectedCode := autoscaling.CheckNoPublicIp.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
