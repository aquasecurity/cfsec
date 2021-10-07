package cloudwatch

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/cloudwatch"

	"testing"
)

func Test_CheckLogGroupCustomerKey_FailureExamples(t *testing.T) {
	expectedCode := cloudwatch.CheckLogGroupCustomerKey.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckLogGroupCustomerKey_PassedExamples(t *testing.T) {
	expectedCode := cloudwatch.CheckLogGroupCustomerKey.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
