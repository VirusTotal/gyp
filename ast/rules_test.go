package ast

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

var ruleWriteSourceTests = []struct {
	Rule           *Rule
	ExpectedSource string
}{
	{
		Rule: &Rule{
			Identifier: "foo",
			Condition:  KeywordTrue,
		},
		ExpectedSource: `
rule foo {
  condition:
    true
}
`,
	},
	{
		Rule: &Rule{
			Identifier: "foo",
			Tags:       []string{"bar", "baz"},
			Condition:  KeywordFalse,
		},
		ExpectedSource: `
rule foo : bar baz {
  condition:
    false
}
`,
	},
	{
		Rule: &Rule{
			Identifier: "foo",
			Global:     true,
			Tags:       []string{"bar", "baz"},
			Condition:  KeywordTrue,
		},
		ExpectedSource: `
global rule foo : bar baz {
  condition:
    true
}
`,
	},
	{
		Rule: &Rule{
			Identifier: "foo",
			Private:    true,
			Tags:       []string{"bar", "baz"},
			Condition:  KeywordTrue,
		},
		ExpectedSource: `
private rule foo : bar baz {
  condition:
    true
}
`,
	},
	{
		Rule: &Rule{
			Identifier: "foo",
			Global:     true,
			Private:    true,
			Tags:       []string{"bar", "baz"},
			Condition:  KeywordTrue,
		},
		ExpectedSource: `
global private rule foo : bar baz {
  condition:
    true
}
`,
	},
	{
		Rule: &Rule{
			Identifier: "foo",
			Meta: []*Meta{
				&Meta{"foo", 1},
				&Meta{"bar", `qux\t\n\xc3\x00☺`},
				&Meta{"baz", true},
			},
			Condition: KeywordTrue,
		},
		ExpectedSource: `
rule foo {
  meta:
    foo = 1
    bar = "qux\t\n\xc3\x00☺"
    baz = true
  condition:
    true
}
`,
	},
	{
		Rule: &Rule{
			Identifier: "foo",
			Strings: []String{
				&TextString{
					BaseString: BaseString{Identifier: "a"},
					ASCII:      true,
					Wide:       true,
					Nocase:     true,
					Xor:        true,
					XorMin:     0,
					XorMax:     255,
					Value:      "bar",
				},
			},
			Condition: KeywordTrue,
		},
		ExpectedSource: `
rule foo {
  strings:
    $a = "bar" ascii wide nocase xor
  condition:
    true
}
`,
	},
}

func TestRuleWriteSource(t *testing.T) {
	for _, test := range ruleWriteSourceTests {
		var b bytes.Buffer
		err := test.Rule.WriteSource(&b)
		assert.NoError(t, err)
		assert.Equal(t, test.ExpectedSource, b.String())
	}
}

func TestGetIdentifier(t *testing.T) {
	rule := &Rule{
		Identifier: "foo",
		Strings: []String{
			&TextString{
				BaseString: BaseString{Identifier: "a"},
				ASCII:      true,
				Wide:       true,
				Nocase:     true,
				Xor:        true,
				XorMin:     0,
				XorMax:     255,
				Value:      "bar",
			},
		},
		Condition: KeywordTrue,
	}

	assert.Equal(t, "a", rule.Strings[0].GetIdentifier())
	assert.Equal(t, "a", rule.Strings[0].(*TextString).Identifier)
}
