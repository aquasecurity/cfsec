package parser

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/cftypes"
	"github.com/liamg/jfather"
	"gopkg.in/yaml.v3"
	"strconv"
)

func setPropertyValueFromJson(node jfather.Node, propertyData *PropertyInner) error {

	switch node.Kind() {

	case jfather.KindNumber:
		propertyData.Type = cftypes.Float64
		return node.Decode(&propertyData.Value)
	case jfather.KindBoolean:
		propertyData.Type = cftypes.Bool
		return node.Decode(&propertyData.Value)
	case jfather.KindString:
		propertyData.Type = cftypes.String
		return node.Decode(&propertyData.Value)
	case jfather.KindObject:
		var childData map[string]*Property
		if err := node.Decode(&childData); err != nil {
			return err
		}
		propertyData.Type = cftypes.Map
		propertyData.Value = childData
		return nil
	case jfather.KindArray:
		var childData []*Property
		if err := node.Decode(&childData); err != nil {
			return err
		}
		propertyData.Type = cftypes.List
		propertyData.Value = childData
		return nil
	default:
		propertyData.Type = cftypes.String
		return node.Decode(&propertyData.Value)
	}

}

func setPropertyValueFromYaml(node *yaml.Node, propertyData *PropertyInner) error {
	if  node.Tag == "!Ref" {
		node.Content = []*yaml.Node{}
		node.Tag = "!!map"
		node.Kind = yaml.MappingNode

		node.Content = append(node.Content, &yaml.Node{
			Tag:         "!!str",
			Value:       "Ref",
			Kind: yaml.ScalarNode,
		})

		node.Content = append(node.Content, &yaml.Node{
			Tag:         "!!str",
			Value:       node.Value,
			Kind: yaml.ScalarNode,
		})
	}

	if node.Content == nil {

		switch node.Tag {

		case "!!int":
			propertyData.Type = cftypes.Int
			propertyData.Value, _ = strconv.Atoi(node.Value)
		case "!!bool":
			propertyData.Type = cftypes.Bool
			propertyData.Value, _ = strconv.ParseBool(node.Value)
		case "!!str", "!!string":
			propertyData.Type = cftypes.String
			propertyData.Value = node.Value
		}
		return nil
	}

	switch node.Tag {
	case "!!map":
		var childData map[string]*Property
		if err := node.Decode(&childData); err != nil {
			return err
		}
		propertyData.Type = cftypes.Map
		propertyData.Value = childData
		return nil
	case "!!seq":
		var childData []*Property
		if err := node.Decode(&childData); err != nil {
			return err
		}
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
