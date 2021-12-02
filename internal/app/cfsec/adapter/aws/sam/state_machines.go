package sam

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/sam"
	"github.com/aquasecurity/defsec/types"
)

func getStateMachines(cfFile parser.FileContext) (stateMachines []sam.StateMachine) {

	stateMachineResources := cfFile.GetResourceByType("AWS::Serverless::StateMachine")
	for _, r := range stateMachineResources {
		stateMachine := sam.StateMachine{
			Metadata:             r.Metadata(),
			Name:                 r.GetStringProperty("Name"),
			LoggingConfiguration: sam.LoggingConfiguration{},
			Tracing:              getTracingConfiguration(r),
		}

		setStateMachinePolicies(r, &stateMachine)
		stateMachines = append(stateMachines, stateMachine)
	}

	return stateMachines
}

func getTracingConfiguration(r *parser.Resource) sam.TracingConfiguration {
	tracing := r.GetProperty("Tracing")
	if tracing.IsNil() {
		return sam.TracingConfiguration{
			Metadata: r.Metadata(),
			Enabled:  types.BoolDefault(false, r.Metadata()),
		}
	}

	return sam.TracingConfiguration{
		Metadata: tracing.Metadata(),
		Enabled:  tracing.GetBoolProperty("Enabled"),
	}
}

func setStateMachinePolicies(r *parser.Resource, stateMachine *sam.StateMachine) {
	policies := r.GetProperty("Policies")
	if policies.IsNotNil() {
		if policies.IsString() {
			stateMachine.ManagedPolicies = append(stateMachine.ManagedPolicies, policies.AsStringValue())
		} else if policies.IsList() {
			for _, property := range policies.AsList() {
				policyDoc, err := getPolicyDocument(property, r.SourceFormat())
				if err != nil {

					stateMachine.ManagedPolicies = append(stateMachine.ManagedPolicies, property.AsStringValue())
					continue
				}
				stateMachine.Policies = append(stateMachine.Policies, *policyDoc)
			}
		}
	}
}
