package cloudfront

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"testing"
)

func Test_EnableLogging_FailureExamples(t *testing.T) {
	expectedCode := "aws-cloudfront-enable-logging"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_EnableLogging_PassedExamples(t *testing.T) {
	expectedCode := "aws-cloudfront-enable-logging"
	test.RunPassingExamplesTest(t, expectedCode)
}
