package parser

import (
	"gopkg.in/yaml.v3"
	"strings"
)

var intrinsicTags = []string{
	"Ref", "GetAtt", "Base64", "FindInMap", "GetAZs",
	"ImportValue", "Join", "Select", "Split", "Sub",
	"Equals", "Cidr", "And", "If", "Not", "Or",
}

var intrinsicFuncs map[string]func(property *Property) *Property

func init() {
	intrinsicFuncs = map[string]func(property *Property) *Property{
		"Ref":        ResolveReference,
		"Fn::Base64": ResolveBase64,
		"Fn::Equals": ResolveEquals,
		"Fn::Join":   ResolveJoin,
		"Fn::Split":  ResolveSplit,
		"Fn::Sub":    PassthroughResolution,
		"Fn::Select": PassthroughResolution,
	}
}

func PassthroughResolution(property *Property) *Property { return property }

func IsIntrinsicFunc(node *yaml.Node) bool {
	if node == nil || node.Tag == "" {
		return false
	}

	for _, tag := range intrinsicTags {
		if strings.TrimPrefix(node.Tag, "!") == tag {
			return true
		}
	}
	return false
}

func IsIntrinsic(key string) bool {
	for tag := range intrinsicFuncs {
		if tag == key {
			return true
		}
	}
	return false
}

func ResolveIntrinsicFunc(property *Property) *Property {
	if !property.IsMap() {
		return property
	}

	for funcName := range property.AsMap() {
		if fn := intrinsicFuncs[funcName]; fn != nil {
			return fn(property)
		}

	}

	return property
}
