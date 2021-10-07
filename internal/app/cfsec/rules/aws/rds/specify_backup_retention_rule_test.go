package rds

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/rds"
)

func Test_CheckBackupRetentionSpecified_FailureExamples(t *testing.T) {
	expectedCode := rds.CheckBackupRetentionSpecified.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckBackupRetentionSpecified_SuccessExamples(t *testing.T) {
	expectedCode := rds.CheckBackupRetentionSpecified.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
