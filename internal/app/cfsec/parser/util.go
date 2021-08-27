package parser

import (
	"strconv"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/cftypes"
	"gopkg.in/yaml.v3"
)

func setPropertyValue(node *yaml.Node, propertyData *propertyInner) error {
	if node.Content == nil {
		switch node.Tag {

		case "!!int":
			propertyData.Type = cftypes.Int
			propertyData.Value, _ = strconv.Atoi(node.Value)
		case "!!bool":
			propertyData.Type = cftypes.Bool
			propertyData.Value, _ = strconv.ParseBool(node.Value)
		case "!!string":
		default:
			propertyData.Type = cftypes.String
			propertyData.Value = node.Value
		}

		return nil
	}

	switch node.Tag {
	case "!!map":
		var childData map[string]*Property
		node.Decode(&childData)
		propertyData.Type = cftypes.Map
		propertyData.Value = childData
		return nil
	case "!!seq":
		var childData []*Property
		node.Decode(&childData)
		propertyData.Type = cftypes.List
		propertyData.Value = childData
		return nil
	}

	return nil
}

func calculateEndLine(node *yaml.Node) int {
	if node.Content == nil {
		return node.Line
	}

	return calculateEndLine(node.Content[len(node.Content)-1])

}
