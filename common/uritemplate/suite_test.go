package uritemplate

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

// Test files from https://github.com/uri-templates/uritemplate-test
var suiteFiles = []string{
	"spec-examples.json",
	"spec-examples-by-section.json",
	"extended-tests.json",
	"negative-tests.json",
}

type suiteGroup struct {
	Variables json.RawMessage      `json:"variables"`
	TestCases [][2]json.RawMessage `json:"testcases"`
}

func TestSuite(t *testing.T) {
	t.Parallel()
	for _, file := range suiteFiles {
		content, err := os.ReadFile(filepath.Join("testdata", file))
		require.NoError(t, err)
		var groups map[string]suiteGroup
		require.NoError(t, json.Unmarshal(content, &groups))
		for name, group := range groups {
			t.Run(file+"/"+name, func(t *testing.T) {
				t.Parallel()
				values, err := decodeSuiteVariables(group.Variables)
				require.NoError(t, err)
				for _, testCase := range group.TestCases {
					var template string
					require.NoError(t, json.Unmarshal(testCase[0], &template))
					var expected any
					require.NoError(t, json.Unmarshal(testCase[1], &expected))
					parsed, err := Parse(template)
					var expanded string
					if err == nil {
						expanded, err = parsed.Expand(values)
					}
					switch expected := expected.(type) {
					case bool:
						require.Error(t, err, template)
					case string:
						require.NoError(t, err, template)
						require.Equal(t, expected, expanded, template)
					case []any:
						require.NoError(t, err, template)
						require.True(t, slices.Contains(expected, any(expanded)), "%s: %q not in %v", template, expanded, expected)
					default:
						t.Fatalf("unexpected result type for %s: %T", template, expected)
					}
				}
			})
		}
	}
}

// decodeSuiteVariables keeps the member order of JSON objects, which is the
// order of associative array pairs.
func decodeSuiteVariables(content json.RawMessage) (Values, error) {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	_, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	values := make(Values)
	for decoder.More() {
		name, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		value, err := decodeSuiteValue(decoder)
		if err != nil {
			return nil, err
		}
		if value != nil {
			values[name.(string)] = value
		}
	}
	return values, nil
}

func decodeSuiteValue(decoder *json.Decoder) (Value, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch token := token.(type) {
	case nil:
		return nil, nil
	case string:
		return String(token), nil
	case json.Number:
		return String(token.String()), nil
	case json.Delim:
		if token == '[' {
			list := List{}
			for decoder.More() {
				member, err := decodeSuiteScalar(decoder)
				if err != nil {
					return nil, err
				}
				list = append(list, member)
			}
			_, err = decoder.Token()
			return list, err
		}
		array := AssociativeArray{}
		for decoder.More() {
			name, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			value, err := decodeSuiteScalar(decoder)
			if err != nil {
				return nil, err
			}
			array = append(array, Pair{Name: name.(string), Value: value})
		}
		_, err = decoder.Token()
		return array, err
	}
	return nil, os.ErrInvalid
}

func decodeSuiteScalar(decoder *json.Decoder) (string, error) {
	token, err := decoder.Token()
	if err != nil {
		return "", err
	}
	switch token := token.(type) {
	case string:
		return token, nil
	case json.Number:
		return token.String(), nil
	}
	return "", os.ErrInvalid
}
