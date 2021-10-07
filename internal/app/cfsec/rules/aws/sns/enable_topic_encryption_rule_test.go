package vpc

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/sns"
)

func Test_CheckEnableTopicEncryption_FailureExamples(t *testing.T) {
	expectedCode := sns.CheckEnableTopicEncryption.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableTopicEncryption_SuccessExamples(t *testing.T) {
	expectedCode := sns.CheckEnableTopicEncryption.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
