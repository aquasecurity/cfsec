package kinesis

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/kinesis"
)

func Test_CheckEnableInTransitEncryption_FailureExamples(t *testing.T) {
	expectedCode := kinesis.CheckEnableInTransitEncryption.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableInTransitEncryption_SuccessExamples(t *testing.T) {
	expectedCode := kinesis.CheckEnableInTransitEncryption.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
