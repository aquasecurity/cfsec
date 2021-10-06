package rds

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
)

func Test_MSK_InTransit_FailureExamples(t *testing.T) {
	expectedCode := "aws-msk-enable-in-transit-encryption"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_MSK_InTransit_SuccessExamples(t *testing.T) {
	expectedCode := "aws-msk-enable-in-transit-encryption"
	test.RunPassingExamplesTest(t, expectedCode)
}
