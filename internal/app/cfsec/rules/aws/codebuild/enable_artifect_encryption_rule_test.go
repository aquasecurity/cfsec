package codebuild

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/codebuild"

	"testing"
)

func Test_CheckEnableEncryption_FailureExamples(t *testing.T) {
	expectedCode := codebuild.CheckEnableEncryption.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableEncryption_PassedExamples(t *testing.T) {
	expectedCode := codebuild.CheckEnableEncryption.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
