package mq

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableGeneralLogging = rules.Register(
	rules.Rule{
		Provider:    provider.AWSProvider,
		Service:     "mq",
		ShortCode:   "enable-general-logging",
		Summary:     "MQ Broker should have general logging enabled",
		Impact:      "Without logging it is difficult to trace issues",
		Resolution:  "Enable general logging",
		Explanation: `Logging should be enabled to allow tracing of issues and activity to be investigated more fully. Logs provide additional information and context which is often invalauble during investigation`,
		Links:       []string{},
		Severity:    severity.Low,
	},
	func(s *state.State) (results rules.Results) {
		for _, broker := range s.AWS.MQ.Brokers {
			if broker.Logging.General.IsFalse() {
				results.Add(
					"Broker does not have general logging enabled.",
					broker.Logging.General,
				)
			}
		}
		return
	},
)
