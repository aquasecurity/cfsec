package rds

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/msk"
)

func Test_CheckEnableInTransitEncryption_FailureExamples(t *testing.T) {
	expectedCode := msk.CheckEnableInTransitEncryption.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableInTransitEncryption_SuccessExamples(t *testing.T) {
	expectedCode := msk.CheckEnableInTransitEncryption.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}
