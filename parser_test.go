package gyp

import (
	"strings"
	"testing"

	"github.com/VirusTotal/gyp/ast"
	"github.com/stretchr/testify/assert"
)

func TestDuplicateRule(t *testing.T) {
	_, err := ParseString(`
rule foo {
  condition:
    false
}
rule foo {
  condition:
    false
}`)
	assert.EqualError(t, err, `line 6: duplicate rule "foo"`)
}

func TestDuplicateTag(t *testing.T) {
	_, err := ParseString(`
rule foo : bar bar {
  condition:
    false
}`)
	assert.EqualError(t, err, `line 2: duplicate tag "bar"`)
}

// All tests in this list must have conditions without of unnecessary parenthesis
// that enforce left-associativity. This is because once the rules are serialized
// to a Protocol Buffer the parenthesis originally in the source are lost, and
// they are added back during deserialization only where needed. For example,
// in (1+2)+3 the parenthesis are not required, the same operation can be written
// as 1+2+3 and the AST for both expressions will look exactly the same once
// converted to its Protol Buffer. While deserializing the AST back from the
// Protol Buffer, there's no way to distinguish one from the other, and the
// AST will be created without the parenthesis. In 1+(2+3) the parenthesis are
// also redudant, but they can restored back because the AST generated for this
// expression is different from the one generated for 1+2+3. So, using 1+(2+3)
// in these tests is OK.
var protoTests = []string{ /*`
	global private rule foo : bar baz {
	  meta:
	    m_int = 1
	    m_neg = -2
	    m_str = "qux"
	    m_true = true
	    m_false = false
	  condition:
	    true
	}`,*/
	`
rule foo {
  condition:
    true and false and true
}`,
	`
rule foo {
  condition:
    false or true or false
}`,
	`
rule foo {
  condition:
    false and true or false
}`,
	`
rule foo {
  condition:
    (false or true) and false
}`,
	`
rule foo {
  condition:
    not false or not (true and false)
}`,
	`
rule foo {
  condition:
    not false or not true and not false
}`,
	`
rule foo {
  condition:
    1 == 2
}`,
	`
rule foo {
  condition:
    1 + 2 - 3 == 0
}`,
	`
rule foo {
  condition:
    1 + (2 - 3) == 0
}`,
	`
rule foo {
  condition:
    1 + 2 - (3 + 4) == 0
}`,
	`
rule foo {
  condition:
    1 - 2 + (3 - 4) == 0
}`,

	/*
			`
		rule foo {
		  condition:
		    1 + (2 - 3) == 5 - 4 \ 4
		}`,
			`
		rule foo {
		  condition:
		    1 + (2 - 3) == -1
		}`,*/
}

var allTests = []string{
	`
rule foo {
  condition:
    false or (true and false)
}`,
	`
rule foo {
  condition:
    (not false) or not (true and false)
}`,
}

func TestWriteSource(t *testing.T) {
	for _, test := range append(protoTests, allTests...) {
		rs, err := ParseString(test)
		assert.NoError(t, err)
		var b strings.Builder
		err = rs.WriteSource(&b)
		assert.NoError(t, err)
		assert.Equal(t, test, b.String())
	}
}

func TestProtos(t *testing.T) {
	for _, test := range protoTests {
		rs, err := ParseString(test)
		assert.NoError(t, err)

		rspb := rs.AsRuleSetProto()
		rs = ast.RuleSetFromProto(rspb)
		assert.NoError(t, err)

		var b strings.Builder
		err = rs.WriteSource(&b)
		assert.NoError(t, err)
		assert.Equal(t, test, b.String())
	}
}
