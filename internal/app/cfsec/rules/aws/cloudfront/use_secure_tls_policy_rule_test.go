package cloudfront

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"testing"
)

func Test_UseSecureTlsPolicy_FailureExamples(t *testing.T) {
	expectedCode := "aws-cloudfront-use-secure-tls-policy"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_UseSecureTlsPolicy_PassedExamples(t *testing.T) {
	expectedCode := "aws-cloudfront-use-secure-tls-policy"
	test.RunPassingExamplesTest(t, expectedCode)
}
