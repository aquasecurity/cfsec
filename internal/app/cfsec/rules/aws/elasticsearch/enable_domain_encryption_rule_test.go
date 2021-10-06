package elasticsearch

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/elasticsearch"
)

func Test_CheckEnableDomainEncryption_FailureExamples(t *testing.T) {
	expectedCode := elasticsearch.CheckEnableDomainEncryption.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableDomainEncryption_PassedExamples(t *testing.T) {
	expectedCode := elasticsearch.CheckEnableDomainEncryption.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
