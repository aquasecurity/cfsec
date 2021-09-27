package s3

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"testing"
)

func Test_EnableBucketEncryption_FailureExamples(t *testing.T) {
	expectedCode := "aws-s3-enable-bucket-encryption"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_EnableBucketEncryption_PassedExamples(t *testing.T) {
	expectedCode := "aws-s3-enable-bucket-encryption"
	test.RunPassingExamplesTest(t, expectedCode)
}
