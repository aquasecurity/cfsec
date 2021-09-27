package dynamodb

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/dynamodb"
)

func Test_CheckEnableAtRestEncryption_FailureExamples(t *testing.T) {
	expectedCode := dynamodb.CheckEnableAtRestEncryption.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableAtRestEncryption_PassedExamples(t *testing.T) {
	expectedCode := dynamodb.CheckEnableAtRestEncryption.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}

