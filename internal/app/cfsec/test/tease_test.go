package test

import (
	"runtime/debug"
	"strings"
	"testing"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/adapter"
	_ "github.com/aquasecurity/cfsec/internal/app/cfsec/loader"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"gopkg.in/yaml.v2"
)

func Test_PanicTeasing(t *testing.T) {
	for _, rule := range scanner.GetRegisteredRules() {
		t.Run(rule.ID(), func(t *testing.T) {
			for _, code := range append(mutateInputs(rule.BadExample...), mutateInputs(rule.GoodExample...)...) {
				func() {
					defer func() {
						if err := recover(); err != nil {
							t.Fatalf("Panic encountered for code:\n\n%s\n\nPanic: %s\n\nStacktrace:\n%s", code, err, string(debug.Stack()))
						}
					}()
					ctx, err := parser.Parse(strings.NewReader(code), "test.yaml")
					if err != nil {
						t.Fatalf("Failed to parse YAML:\n\n%s\n\nError: %s", code, err)
					}
					state := adapter.Adapt(*ctx)
					_ = rule.Base.Evaluate(state)
				}()
			}
		})
	}

}

func mutateInputs(input ...string) []string {
	var output []string
	for _, code := range input {
		output = append(output, mutate(code)...)
	}
	return output
}

func mutate(input string) []string {
	var output []string

	world := make(map[interface{}]interface{})
	if err := yaml.Unmarshal([]byte(input), world); err != nil {
		return nil
	}

	if _, ok := world["Resources"]; !ok {
		return nil
	}

	changed := true
	for changed {
		if mutateWorld(world, 0) {
			data, err := yaml.Marshal(world)
			if err != nil {
				break
			}
			output = append(output, string(data))
		}
		changed = shrinkWorld(world, 0)
		data, err := yaml.Marshal(world)
		if err != nil {
			break
		}
		output = append(output, string(data))
	}

	return output
}

const MIN_DEPTH = 3

func mutateWorld(world map[interface{}]interface{}, depth int) bool {
	var changed bool
	for key, val := range world {
		switch typeVal := val.(type) {
		case string:
			if depth >= MIN_DEPTH {
				world[key] = 123
				changed = true
			}
		case map[interface{}]interface{}:
			changed = mutateWorld(typeVal, depth+1) || changed
			world[key] = typeVal
		default:
			if depth >= MIN_DEPTH {
				world[key] = "blah"
				changed = true
			}
		}
	}
	return changed
}

func shrinkWorld(world map[interface{}]interface{}, depth int) bool {
	var changed bool
	for key, val := range world {
		switch typeVal := val.(type) {
		case map[interface{}]interface{}:
			if len(typeVal) == 0 {
				delete(world, key)
				changed = true
				continue
			}
			if depth >= MIN_DEPTH {
				changed = shrinkWorld(typeVal, depth+1) || changed
				world[key] = typeVal
			}
		default:
			if depth >= MIN_DEPTH {
				delete(world, key)
				changed = true
			}
		}
	}
	return changed

}
