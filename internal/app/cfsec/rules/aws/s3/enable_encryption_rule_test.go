package s3

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/s3"

	"testing"
)

func Test_CheckEncryptionIsEnabled_FailureExamples(t *testing.T) {
	expectedCode := s3.CheckEncryptionIsEnabled.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEncryptionIsEnabled_PassedExamples(t *testing.T) {
	expectedCode := s3.CheckEncryptionIsEnabled.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
