package cloudfront

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"testing"
)

func Test_EnforceHttps_FailureExamples(t *testing.T) {
	expectedCode := "aws-cloudfront-enforce-https"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_EnforceHttps_PassedExamples(t *testing.T) {
	expectedCode := "aws-cloudfront-enforce-https"
	test.RunPassingExamplesTest(t, expectedCode)
}
