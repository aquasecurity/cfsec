package elasticache

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/elasticache"
)

func Test_CheckEnableInTransitEncryption_FailureExamples(t *testing.T) {
	expectedCode := elasticache.CheckEnableInTransitEncryption.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableInTransitEncryption_PassedExamples(t *testing.T) {
	expectedCode := elasticache.CheckEnableInTransitEncryption.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
