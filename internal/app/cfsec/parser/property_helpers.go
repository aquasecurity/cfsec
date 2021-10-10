package parser

import (
	"strings"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/cftypes"
	"github.com/aquasecurity/defsec/types"
)

// IsNil ...
func (p *Property) IsNil() bool {
	return p == nil || p.Inner.Value == nil
}

// IsNotNil ...
func (p *Property) IsNotNil() bool {
	return !p.IsNil()
}

// IsString ...
func (p *Property) IsString() bool {
	if p.IsNil() {
		return false
	}
	if p.isFunction() {
		prop := p.resolveValue()
		if prop != p {
			return prop.IsString()
		}
	}
	return p.Inner.Type == cftypes.String
}

// IsNotString ...
func (p *Property) IsNotString() bool {
	return !p.IsString()
}

// IsInt ...
func (p *Property) IsInt() bool {
	if p.IsNil() {
		return false
	}
	if p.isFunction() {
		prop := p.resolveValue()
		if prop != p {
			return prop.IsInt()
		}
	}
	return p.Inner.Type == cftypes.Int
}

// IsNotInt ...
func (p *Property) IsNotInt() bool {
	return !p.IsInt()
}

// IsMap ...
func (p *Property) IsMap() bool {
	if p.IsNil() {
		return false
	}
	return p.Inner.Type == cftypes.Map
}

// IsNotMap ...
func (p *Property) IsNotMap() bool {
	return !p.IsMap()
}

// IsList ...
func (p *Property) IsList() bool {
	if p.IsNil() {
		return false
	}
	if p.isFunction() {
		prop := p.resolveValue()
		if prop != p {
			return prop.IsList()
		}
	}
	return p.Inner.Type == cftypes.List
}

// IsNotList ...
func (p *Property) IsNotList() bool {
	return !p.IsList()
}

// IsBool ...
func (p *Property) IsBool() bool {
	if p.IsNil() {
		return false
	}
	if p.isFunction() {
		prop := p.resolveValue()
		if prop != p {
			return prop.IsBool()
		}
	}
	return p.Inner.Type == cftypes.Bool
}

// IsNotBool ...
func (p *Property) IsNotBool() bool {
	return !p.IsBool()
}

// AsString ...
func (p *Property) AsString() string {
	if p.isFunction() {
		prop := p.resolveValue()
		if prop != p {
			return prop.AsString()
		}
	}
	return p.Inner.Value.(string)
}

// AsStringValue ...
func (p *Property) AsStringValue() types.StringValue {
	return types.StringExplicit(p.AsString(), p.Metadata())
}

// AsInt ...
func (p *Property) AsInt() int {
	if p.isFunction() {
		return p.resolveValue().AsInt()
	}
	return p.Inner.Value.(int)
}

// AsIntValue ...
func (p *Property) AsIntValue() types.IntValue {
	return types.IntExplicit(p.AsInt(), p.Metadata())
}

// AsBool ...
func (p *Property) AsBool() bool {
	if p.isFunction() {
		return p.resolveValue().AsBool()
	}
	return p.Inner.Value.(bool)
}

// AsBoolValue ...
func (p *Property) AsBoolValue() types.BoolValue {
	return types.Bool(p.AsBool(), p.Metadata())
}

// AsMap ...
func (p *Property) AsMap() map[string]*Property {
	return p.Inner.Value.(map[string]*Property)
}

// AsList ...
func (p *Property) AsList() []*Property {
	if p.isFunction() {
		prop := p.resolveValue()
		if prop != p {
			return prop.AsList()
		}
	}

	if list, ok := p.Inner.Value.([]*Property); ok {
		return list
	}
	return nil
}

// EqualTo ...
func (p *Property) EqualTo(checkValue interface{}, equalityOptions ...EqualityOptions) bool {
	var ignoreCase bool
	for _, option := range equalityOptions {
		if option == IgnoreCase {
			ignoreCase = true
		}
	}

	if p.IsNil() {
		return checkValue == nil
	}

	if p.RawValue() == checkValue {
		return true
	}

	switch p.Inner.Type {
	case cftypes.String:
		if ignoreCase {
			return strings.EqualFold(p.AsString(), checkValue.(string))
		}
		return p.AsString() == checkValue.(string)
	case cftypes.Int:
		if val, ok := checkValue.(int); ok {
			return p.AsInt() == val
		}
	}
	return false
}

// IsTrue ...
func (p *Property) IsTrue() bool {
	if p.IsNil() || !p.IsBool() {
		return false
	}

	return p.AsBool()
}

// IsEmpty ...
func (p *Property) IsEmpty() bool {

	if p.IsNil() {
		return true
	}

	switch p.Inner.Type {
	case cftypes.String:
		return p.AsString() == ""
	case cftypes.List, cftypes.Map:
		return len(p.AsList()) == 0
	default:
		return false
	}
}

// Contains ...
func (p *Property) Contains(checkVal interface{}) bool {
	if p == nil || p.IsNil() {
		return false
	}

	switch p.Type() {
	case cftypes.List:
		for _, p := range p.AsList() {
			if p.EqualTo(checkVal) {
				return true
			}
		}
	case cftypes.Map:
		for key := range p.AsMap() {
			if key == checkVal.(string) {
				return true
			}
		}
	case cftypes.String:
		return strings.Contains(p.AsString(), checkVal.(string))
	}
	return false
}

