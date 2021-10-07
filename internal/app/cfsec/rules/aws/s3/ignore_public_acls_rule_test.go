package s3

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/s3"

	"testing"
)

func Test_CheckPublicACLsAreIgnored_FailureExamples(t *testing.T) {
	expectedCode := s3.CheckPublicACLsAreIgnored.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckPublicACLsAreIgnored_PassedExamples(t *testing.T) {
	expectedCode := s3.CheckPublicACLsAreIgnored.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
