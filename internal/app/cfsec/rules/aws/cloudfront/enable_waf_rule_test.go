package cloudfront

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"testing"
)

func Test_EnableWaf_FailureExamples(t *testing.T) {
	expectedCode := "aws-cloudfront-enable-waf"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_EnableWaf_PassedExamples(t *testing.T) {
	expectedCode := "aws-cloudfront-enable-waf"
	test.RunPassingExamplesTest(t, expectedCode)
}
