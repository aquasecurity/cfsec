package parser

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

var intrinsicTags = []string{
	"Ref", "GetAtt", "Base64", "FindInMap", "GetAZs",
	"ImportValue", "Join", "Select", "Split", "Sub",
	"Equals", "Cidr", "And", "If", "Not", "Or",
}

var intrinsicFuncs map[string]func(property *Property) (*Property,bool)

func init() {
	intrinsicFuncs = map[string]func(property *Property) (*Property, bool) {
		"Ref":           ResolveReference,
		"Fn::Base64":    ResolveBase64,
		"Fn::Equals":    ResolveEquals,
		"Fn::Join":      ResolveJoin,
		"Fn::Split":     ResolveSplit,
		"Fn::Sub":       ResolveSub,
		"Fn::FindInMap": ResolveFindInMap,
		"Fn::Select":    ResolveSelect,
		"Fn::GetAtt":    ResolveGetAtt,
		"Fn::GetAZs":    GetAzs,
		"Fn::Cidr":      GetCidr,
	}
}

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

// IsIntrinsic ...
func IsIntrinsic(key string) bool {
	for tag := range intrinsicFuncs {
		if tag == key {
			return true
		}
	}
	return false
}

// ResolveIntrinsicFunc ...
func ResolveIntrinsicFunc(property *Property) (*Property, bool) {
	if !property.IsMap() {
		return property, true
	}

	for funcName := range property.AsMap() {
		if fn := intrinsicFuncs[funcName]; fn != nil {
			return fn(property)
		}
	}
	return property, false
}

func getIntrinsicTag(tag string) string {
	tag = strings.TrimPrefix(tag, "!")
	switch tag {
	case "Ref", "Contains":
		return tag
	default:
		return fmt.Sprintf("Fn::%s", tag)
	}
}

func abortIntrinsic(property *Property, msg string, components ...string) (*Property, bool) {
	_, _ = fmt.Fprintln(os.Stderr, fmt.Sprintf(msg, components))
	_, _ = fmt.Fprintln(os.Stderr, fmt.Sprintf("occurred %s:%d", property.rng.GetFilename(), property.rng.GetStartLine()))
	return property, false
}
