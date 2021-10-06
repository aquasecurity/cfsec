package cloudwatch

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"testing"
)

func Test_AutoscalingCheckEnableAtRestEncryption_FailureExamples(t *testing.T) {
	expectedCode := "aws-cloudwatch-log-group-customer-key"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_AutoscalingCheckEnableAtRestEncryption_PassedExamples(t *testing.T) {
	expectedCode := "aws-cloudwatch-log-group-customer-key"
	test.RunPassingExamplesTest(t, expectedCode)
}
