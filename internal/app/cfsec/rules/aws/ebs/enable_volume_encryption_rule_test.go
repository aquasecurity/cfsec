package ebs

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/ebs"
)

func Test_CheckEnableVolumeEncryption_FailureExamples(t *testing.T) {
	expectedCode := ebs.CheckEnableVolumeEncryption.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableVolumeEncryption_PassedExamples(t *testing.T) {
	expectedCode := ebs.CheckEnableVolumeEncryption.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
