package rds

import (
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
)

func Test_MQ_Public_FailureExamples(t *testing.T) {
	expectedCode := "aws-mq-no-public-access"
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_MQ_Public_SuccessExamples(t *testing.T) {
	expectedCode := "aws-mq-no-public-access"
	test.RunPassingExamplesTest(t, expectedCode)
}
