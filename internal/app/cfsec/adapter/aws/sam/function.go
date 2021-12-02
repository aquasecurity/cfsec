package sam

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/util"
	"github.com/aquasecurity/defsec/provider/aws/iam"
	"github.com/aquasecurity/defsec/provider/aws/sam"
)

func getFunctions(cfFile parser.FileContext) (functions []sam.Function) {

	functionResources := cfFile.GetResourceByType("AWS::Serverless::Function")
	for _, r := range functionResources {
		function := sam.Function{
			Metadata:     r.Metadata(),
			FunctionName: r.GetStringProperty("FunctionName"),
			Tracing:      r.GetStringProperty("Tracing", sam.TracingModePassThrough),
		}

		setFunctionPolicies(r, &function)
		functions = append(functions, function)
	}

	return functions
}

func setFunctionPolicies(r *parser.Resource, function *sam.Function) {
	policies := r.GetProperty("Policies")
	if policies.IsNotNil() {
		if policies.IsString() {
			function.ManagedPolicies = append(function.ManagedPolicies, policies.AsStringValue())
		} else if policies.IsList() {
			for _, property := range policies.AsList() {
				if property.IsMap() {
					policyDoc, err := getPolicyDocument(property, r.SourceFormat())
					if err != nil {

						function.ManagedPolicies = append(function.ManagedPolicies, property.AsStringValue())
						continue
					}
					function.Policies = append(function.Policies, *policyDoc)
				} else {
					function.ManagedPolicies = append(function.ManagedPolicies, property.AsStringValue())
				}

			}
		}
	}
}

func getPolicyDocument(policyProp *parser.Property, sourceFormat parser.SourceFormat) (*iam.PolicyDocument, error) {
	policyDoc := util.GetJsonBytes(policyProp, sourceFormat, true)

	return iam.ParsePolicyDocument(policyDoc, policyProp.Metadata())
}
