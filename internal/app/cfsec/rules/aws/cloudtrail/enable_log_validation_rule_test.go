package cloudtrail
import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/test"
	"github.com/aquasecurity/defsec/rules/aws/cloudtrail"
	"testing"
)

func Test_CheckEnableLogValidation_FailureExamples(t *testing.T) {
	expectedCode := cloudtrail.CheckEnableLogValidation.Rule().LongID()
	test.RunFailureExamplesTest(t, expectedCode)
}

func Test_CheckEnableLogValidation_PassedExamples(t *testing.T) {
	expectedCode := cloudtrail.CheckEnableLogValidation.Rule().LongID()
	test.RunPassingExamplesTest(t, expectedCode)
}



