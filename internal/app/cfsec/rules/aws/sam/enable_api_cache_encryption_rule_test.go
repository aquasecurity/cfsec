package sam

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/sam"

	"testing"
)

func Test_CheckEnableApiCacheEncryption_FailureExamples(t *testing.T) {
	expectedCode := sam.CheckEnableApiCacheEncryption.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableApiCacheEncryption_PassedExamples(t *testing.T) {
	expectedCode := sam.CheckEnableApiCacheEncryption.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
