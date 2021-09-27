package s3

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"testing"
)

func Test_BlockPublicAcls_FailureExamples(t *testing.T) {
	expectedCode := "aws-s3-no-public-access-with-acl"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_BlockPublicAcls_PassedExamples(t *testing.T) {
	expectedCode := "aws-s3-no-public-access-with-acl"
	test.RunPassingExamplesTest(t, expectedCode)
}