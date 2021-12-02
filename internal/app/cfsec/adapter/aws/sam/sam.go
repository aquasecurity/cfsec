package sam

import (
	"reflect"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/debug"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/sam"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (sam sam.SAM) {
	defer func() {
		if r := recover(); r != nil {
			metadata := cfFile.Metadata()
			debug.Log("There were errors adapting %s from %s", reflect.TypeOf(sam), metadata.Range().GetFilename())
		}
	}()

	sam.APIs = getApis(cfFile)
	sam.HttpAPIs = getHttpApis(cfFile)
	sam.Functions = getFunctions(cfFile)
	sam.StateMachines = getStateMachines(cfFile)
	sam.SimpleTables = getSimpleTables(cfFile)
	return sam
}
