package s3

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"testing"
)

func Test_EnableBucketLogging_FailureExamples(t *testing.T) {
	expectedCode := "aws-s3-enable-bucket-logging"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_EnableBucketLogging_PassedExamples(t *testing.T) {
	expectedCode := "aws-s3-enable-bucket-logging"
	test.RunPassingExamplesTest(t, expectedCode)
}
