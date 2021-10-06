package elasticsearch

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/elasticsearch"
)

func Test_CheckEnableDomainLogging_FailureExamples(t *testing.T) {
	expectedCode := elasticsearch.CheckEnableDomainLogging.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableDomainLogging_PassedExamples(t *testing.T) {
	expectedCode := elasticsearch.CheckEnableDomainLogging.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
