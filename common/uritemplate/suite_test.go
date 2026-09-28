package uritemplate

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"

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
	Variables map[string]suiteValue `json:"variables"`
	TestCases []suiteTestCase       `json:"testcases"`
}

func (g *suiteGroup) values() Values {
	values := make(Values, len(g.Variables))
	for name, value := range g.Variables {
		values[name] = value.Value
	}
	return values
}

type suiteTestCase struct {
	Template string
	Expected suiteExpected
}

func (c *suiteTestCase) UnmarshalJSON(content []byte) error {
	var rawTestCase []json.RawMessage
	err := json.Unmarshal(content, &rawTestCase)
	if err != nil {
		return err
	}
	if len(rawTestCase) != 2 {
		return E.New("expected test case of 2 elements, got ", len(rawTestCase))
	}
	err = json.Unmarshal(rawTestCase[0], &c.Template)
	if err != nil {
		return E.Cause(err, "decode template")
	}
	err = json.Unmarshal(rawTestCase[1], &c.Expected)
	if err != nil {
		return E.Cause(err, "decode expected result for ", c.Template)
	}
	return nil
}

// suiteExpected is false for a template that must fail, or a string or an
// array of acceptable expansions.
type suiteExpected struct {
	Error      bool
	Candidates []string
}

func (e *suiteExpected) UnmarshalJSON(content []byte) error {
	var failed bool
	err := json.Unmarshal(content, &failed)
	if err == nil {
		if failed {
			return E.New("unexpected result: true")
		}
		e.Error = true
		return nil
	}
	var candidate string
	err = json.Unmarshal(content, &candidate)
	if err == nil {
		e.Candidates = []string{candidate}
		return nil
	}
	return json.Unmarshal(content, &e.Candidates)
}

// suiteValue decodes null as undefined, a string or number as String, an array
// as List, and an object as AssociativeArray in member order.
type suiteValue struct {
	Value Value
}

func (v *suiteValue) UnmarshalJSON(content []byte) error {
	if string(content) == "null" {
		v.Value = nil
		return nil
	}
	var list []suiteScalar
	err := json.Unmarshal(content, &list)
	if err == nil {
		v.Value = List(common.Map(list, func(it suiteScalar) string { return string(it) }))
		return nil
	}
	var object badjson.TypedMap[string, suiteScalar]
	err = json.Unmarshal(content, &object)
	if err == nil {
		array := AssociativeArray{}
		for _, entry := range object.Entries() {
			array = append(array, Pair{Name: entry.Key, Value: string(entry.Value)})
		}
		v.Value = array
		return nil
	}
	var scalar suiteScalar
	err = json.Unmarshal(content, &scalar)
	if err != nil {
		return err
	}
	v.Value = String(scalar)
	return nil
}

// suiteScalar is a string, or a number kept in its literal form.
type suiteScalar string

func (s *suiteScalar) UnmarshalJSON(content []byte) error {
	var value string
	err := json.Unmarshal(content, &value)
	if err == nil {
		*s = suiteScalar(value)
		return nil
	}
	var number float64
	err = json.Unmarshal(content, &number)
	if err != nil {
		return err
	}
	*s = suiteScalar(content)
	return nil
}

func TestSuite(t *testing.T) {
	t.Parallel()
	for _, file := range suiteFiles {
		content, err := os.ReadFile(filepath.Join("testdata", file))
		require.NoError(t, err)
		groups, err := json.UnmarshalExtended[map[string]suiteGroup](content)
		require.NoError(t, err)
		for name, group := range groups {
			t.Run(file+"/"+name, func(t *testing.T) {
				t.Parallel()
				values := group.values()
				for _, testCase := range group.TestCases {
					template := testCase.Template
					parsed, err := Parse(template)
					var expanded string
					if err == nil {
						expanded, err = parsed.Expand(values)
					}
					if testCase.Expected.Error {
						require.Error(t, err, template)
						continue
					}
					require.NoError(t, err, template)
					require.True(t, slices.Contains(testCase.Expected.Candidates, expanded), "%s: %q not in %v", template, expanded, testCase.Expected.Candidates)
				}
			})
		}
	}
}
