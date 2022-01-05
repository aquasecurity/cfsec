package hacking

import (
	_ "github.com/aquasecurity/cfsec/internal/app/cfsec/loader"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
)

func GetRules() []rules.Rule {
	return scanner.GetRegisteredRules()
}
