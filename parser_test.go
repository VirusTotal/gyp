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

func TestDuplicateModifier(t *testing.T) {
	_, err := ParseString(`
rule foo  {
  strings:
	$a = "foo" wide wide
  condition:
    $a
}`)
	assert.EqualError(t, err, `line 4: duplicate modifier`)
}


func TestNonAscii(t *testing.T) {
  _, err := ParseString("rule \x12 foo { condition: false }")
  assert.EqualError(t, err, `line 1: non-ascii character "\x12"`)
}


// All tests in this list must have conditions without of unnecessary parenthesis
// that enforce left-associativity. This is because once the rules are serialized
// to a Protocol Buffer the parenthesis originally in the source are lost, and
// they are added back during deserialization only where needed. For example,
// in (1+2)+3 the parenthesis are not required, the same operation can be written
// as 1+2+3 and the AST for both expressions will look exactly the same once
// converted to its Protocol Buffer. While deserializing the AST back from the
// Protocol Buffer, there's no way to distinguish one from the other, and the
// AST will be created without the parenthesis. In 1+(2+3) the parenthesis are
// also redundant, but they be can restored back because the AST generated for
// this expression is different from the one generated for 1+2+3. So, using
// 1+(2+3) in these tests is OK.
var protoTests = []string{
	`
global private rule foo : bar baz {
  meta:
    m_int = 1
    m_neg = -2
    m_str = "qux"
    m_true = true
    m_false = false
  condition:
    true
}`,
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
    1 - (2 + 3) == 0
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
	`
rule foo {
  condition:
    1 + (2 - 3) % 1 != 5 * 1 - 4 \ 4
}`,
	`
rule foo {
  condition:
    1 < 2 and 3 > 4
}`,
	`
rule foo {
  condition:
    1 <= 2 and 3 >= 4
}`,
	`
rule foo {
  condition:
    1 << (2 >> 2)
}`,
	`
rule foo {
  condition:
    1 & (2 | 2) == 1
}`,
	`
rule foo {
  condition:
    --1 + 1 == 1
}`,
	`
rule foo {
  condition:
    -(-1 + 1) == 1
}`,
	`
rule foo {
  strings:
    $a = "bar"
  condition:
    $a
}`,
	`
rule foo {
  strings:
    $a = "bar"
  condition:
    $a at 10 + 10
}`,
	`
rule foo {
  strings:
    $a = "bar"
  condition:
    #a > 5
}`,
	`
rule foo {
  strings:
    $a = "foo\\bar"
  condition:
    $a
}`,
	`
rule foo {
  strings:
    $a = "bar"
  condition:
    $a at 4 + 2
}`,
	`
rule foo {
  strings:
    $a = "bar"
  condition:
    @a == 10 and @a[2] == 20
}`,
	`
rule foo {
  strings:
    $a = "bar" ascii wide nocase fullword xor(10-20)
  condition:
    $a in (5 * 5..6 * 6)
}`,
	`
rule foo {
  condition:
    int32(0) == 0
}`,
	`
rule foo {
  condition:
    foo[0] == 0
}`,
	`
rule foo {
  condition:
    foo(1, 2 + 3, 4) == bar()
}`,
	`
rule foo {
  condition:
    "foobar" contains "foo"
}`,
	`
rule foo {
  condition:
    for all section in pe.sections : (section.name != ".text")
}`,
	`
rule foo {
  condition:
    for any i in (1..2) : (i < 3)
}`,
	`
rule foo {
  condition:
    for 3 i in (1,2,3) : (i < 4)
}`,
	`
rule foo {
  strings:
    $a = "foo"
    $b = "bar"
  condition:
    for all of ($a,$b) : ($)
}`,
	`
rule foo {
  strings:
    $a = "foo"
    $b = "bar"
  condition:
    all of ($a,$b)
}`,
	`
rule foo {
  strings:
    $a = "foo"
    $b = "bar"
  condition:
    any of ($a*)
}`,
	`
rule foo {
  strings:
    $a = /a\.bc/ wide nocase
  condition:
    $a
}`,
	`
rule foo {
  strings:
    $a = /a\.bc/is
  condition:
    $a
}`,
	`
rule foo {
  condition:
    "foobarbaz" matches /foo.*baz/is
}`,
	`
rule foo {
  condition:
    some_function(/abc/is)
}`,
	`
rule foo {
  strings:
    $a = { 01 02 03 04 ?? AA B? ?C }
  condition:
    $a
}`,
	`
rule foo {
  strings:
    $a = { 01 02 ( 03 04 | 05 06 ) 07 08 09 }
  condition:
    $a
}`,
	`
rule foo {
  strings:
    $a = { 01 02 [2] 03 04 [1-2] 05 06 [1-] 07 08 [-] 09 0A }
  condition:
    $a
}`,
}

// These tests won't pass the protobuf serialization-deserialization cycle.
var nonProtoTests = []string{
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
	`
rule foo {
  condition:
    (1 <= 2) and (3 >= 4)
}`,

	// This test is not included in protoTests because during the protobuf
	// serialization the strings are unescaped and \x07 is converted to the
	// "bell" character. When restoring the AST back from the protobuf the "bell"
	// character is encoded as \a and therefore the rules are not same.
	`
rule foo {
  strings:
    $a = "foo\x07bar"
  condition:
    $a
}`,
}

func TestWriteSource(t *testing.T) {
	for _, test := range append(protoTests, nonProtoTests...) {
		rs, err := ParseString(test)
		if !assert.NoError(t, err) {
			break
		}
		var b strings.Builder
		err = rs.WriteSource(&b)
		if !assert.NoError(t, err) {
			break
		}
		if !assert.Equal(t, test, b.String()) {
			break
		}
	}
}

func TestProtos(t *testing.T) {
	for _, test := range protoTests {
		rs, err := ParseString(test)
		if !assert.NoError(t, err) {
			break
		}
		rspb := rs.AsProto()
		rs = ast.RuleSetFromProto(rspb)
		if !assert.NoError(t, err) {
			break
		}
		var b strings.Builder
		err = rs.WriteSource(&b)
		if !assert.NoError(t, err) {
			break
		}
		if !assert.Equal(t, test, b.String()) {
			break
		}
	}
}
