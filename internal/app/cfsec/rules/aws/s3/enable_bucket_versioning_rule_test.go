package s3

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"testing"
)

func Test_EnableBucketVersioning_FailureExamples(t *testing.T) {
	expectedCode := "aws-s3-enable-versioning"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_EnableBucketVersioning_PassedExamples(t *testing.T) {
	expectedCode := "aws-s3-enable-versioning"
	test.RunPassingExamplesTest(t, expectedCode)
}
