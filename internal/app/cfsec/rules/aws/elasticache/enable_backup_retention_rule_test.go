package elasticache

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/elasticache"
)

func Test_CheckEnableBackupRetention_FailureExamples(t *testing.T) {
	expectedCode := elasticache.CheckEnableBackupRetention.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableBackupRetention_PassedExamples(t *testing.T) {
	expectedCode := elasticache.CheckEnableBackupRetention.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
