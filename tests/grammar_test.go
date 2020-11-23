package tests

import (
	"github.com/VirusTotal/gyp/ast"
	"strings"
	"testing"

	"github.com/VirusTotal/gyp"
	"github.com/stretchr/testify/assert"
)

var testRules = `
rule BASIC_BOOL {
  condition:
    true
}

rule BASIC_BOOL2 {
  condition:
    false
}

rule HEX_STRING1 {
  strings:
    $h1 = { 01 23 45 67 89 AB }
    $h2 = { CD EF 01 23 45 67 }
  condition:
    any of ($h*)
}

rule HEX_STRING2 {
  strings:
    $h1 = { 01 23 ( 45 67 | 89 AB | CD ) ?? ?A ?B }
    $h2 = { CD EF 01 [10-20] 23 45 [-] 67 }
    $h3 = { CD EF 01 [10-20] 23 45 [30-] 67 }
    $h4 = { CD ?? 01 [5] 23 }
    $h5 = { 01 23 ( 45 [30-35] 67 | 89 [40] AB [50-60] CD ) ?? ?A ?B }
  condition:
    any of ($h*)
}

rule REGEX1 {
  strings:
    $r1 = /first regex/
  condition:
    $r1
}

rule REGEX2 {
  strings:
    $r1 = /regex with mod i/i
    $r2 = /regex with mod s/s
  condition:
    $r1 or $r2
}

rule STRING1 {
  strings:
    $s1 = "ABCDEFG"
  condition:
    $s1
}

rule STRING2 {
  strings:
    $s1 = "ABCDEFG"
    $s2 = "HIJKLMN"
  condition:
    $s1 or $s2
}

rule STRING_MODIFIERS {
  strings:
    $s1 = "foo" ascii wide nocase fullword private base64 base64wide xor
    $s2 = "bar" xor(1)
    $s3 = "baz" xor(2-4)
    $s4 = "qux" base64("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
    $s5 = "qux" base64wide("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
  condition:
    all of them
}

rule STRING_ESCAPED_CHARS {
  strings:
    $s1 = "C:\\Foo\"\\Bar\n"
    $s2 = "\""
    $s3 = "\\"
  condition:
    $s1 and $s2 and $s3
}

rule TAG : tag1 {
  condition:
    true
}

rule TAG_STRING : tag2 {
  strings:
    $s1 = "ABCDEFG"
  condition:
    $s1
}

rule TAGS : tag1 tag2 tag3 {
  condition:
    true
}

global rule GLOBAL {
  condition:
    true
}

private rule PRIVATE {
  condition:
    true
}

rule META {
  meta:
    meta_str = "string metadata"
    meta_int = 42
    meta_neg = -42
    meta_true = true
    meta_false = false
  condition:
    true
}

rule XOR {
  strings:
    $xor1 = "xor!" xor
    $xor2 = "xor?" nocase xor
    $no_xor1 = "no xor :(" wide
    $no_xor2 = "no xor >:(" ascii nocase
  condition:
    any of them
}

rule OCCURRENCES {
  strings:
    $a = "str1"
    $b = "str2"
    $c = "str3"
  condition:
    #a == 20 and #b < 5 and #c >= 30
}

rule FOR_IN1 {
  strings:
    $a = "str1"
    $b = "str2"
    $c = "str3"
  condition:
    for any i in (5, 10, 15) : (@a[i] % 6 == @c[i * 2])
}

rule FOR_IN2 {
  strings:
    $a = "str1"
    $b = "str2"
    $c = "str3"
  condition:
    for any k,v in some_dict : (k == "foo" and v == "bar")
}

rule FOR_OF {
  meta:
    description = "for..of rule"
  strings:
    $a = "str"
    $b = /regex/
    $c = { 00 11 22 }
  condition:
    for all of ($a, $b, $c) : ($ at entrypoint)
}

rule INTEGER_FUNCTION {
  condition:
    uint8(500) == 3470 and uint16(uint32(100)) == 275
}

rule MATCHES {
  condition:
    some_string matches /[a-z0-9]*/i
}

rule CONTAINS {
  condition:
    some_string contains "this string"
}

rule NOT {
  condition:
    not that_var and this_var < 500
}

rule PRECEDENCE_NO_PARENS {
  condition:
    "foo" | "bar" >> 5
}

rule PRECEDENCE_PARENS {
  condition:
    ("foo" | "bar") >> 5
}

rule RANGE {
  strings:
    $a = "str1"
    $b = "str2"
  condition:
    $a in (0..100) and $b in (100..filesize)
}

rule SET_OF_STRINGS {
  strings:
    $foo1 = "foo1"
    $foo2 = "foo2"
    $foo3 = "foo3"
    $foo4 = "foo4"
  condition:
    2 of ($foo1, $foo2, $foo4*)
}

rule AND_OR_PRECEDENCE_NO_PARENS {
  strings:
    $foo1 = "foo1"
    $foo2 = /foo2/
    $foo3 = { AA BB CC }
  condition:
    $foo1 or $foo2 or $foo3 and $foo4
}

rule AND_OR_PRECEDENCE_PARENS {
  strings:
    $foo1 = "foo1"
    $foo2 = /foo2/
    $foo3 = { AA BB CC }
  condition:
    ($foo1 or $foo2 or $foo3) and $foo4
}

rule STRING_LENGTH {
  strings:
    $foo1 = /foo(1)+/
  condition:
    for all i in (5, 10, 15) : (!foo1[i] >= 20)
}

rule MODULE {
  condition:
    foo.bar(10, 20, 30) != /(test){1}/
}
`

func TestRulesetParsing(t *testing.T) {
	ruleset, err := gyp.ParseString(testRules)
	assert.NoError(t, err)

	var b strings.Builder
	serializer := gyp.NewSerializer(&b)
	serializer.SetIndent("  ")
	err = serializer.Serialize(ruleset.AsProto())
	assert.NoError(t, err)

	output := b.String()
	assert.Equal(t, testRules, output)
}

func TestParsing(t *testing.T) {
	// Parse rule and build AST.
	ruleset, err := gyp.ParseString(testRules)
	assert.NoError(t, err)
	// Write rules from AST back to text.
	var b strings.Builder
	err = ruleset.WriteSource(&b)
	assert.NoError(t, err)
	// Make sure they are equal to the original sources.
	output := b.String()
	assert.Equal(t, testRules, output)
}

func TestProtoSerialization(t *testing.T) {
	// Parse rule and build AST.
	ruleset, err := gyp.ParseString(testRules)
	assert.NoError(t, err)
	// Convert AST to proto.
	pbRuleset := ruleset.AsProto()
	assert.NotNil(t, pbRuleset)
	// Convert the proto back to AST.
	ruleset = ast.RuleSetFromProto(pbRuleset)
	assert.NotNil(t, ruleset)
	// Recover rules sources from AST.
	var b strings.Builder
	err = ruleset.WriteSource(&b)
	assert.NoError(t, err)
	// Make sure they are equal to the original sources.
	assert.Equal(t, testRules, b.String())
}

func TestBase64AlphabetLength(t *testing.T) {
	_, err := gyp.ParseString(`
	rule BASE64 {
		strings:
			$foo = "foo" base64("baz")
	}`)
	assert.Error(t, err, "length of base64 alphabet must be 64")
}

func TestUnevenNumberOfDigits(t *testing.T) {
	_, err := gyp.ParseString(`
	rule UNEVEN_HEX_STRING {
		strings:
			$s1 = {012 010203}
		condition:
			all of them
	}`)
	if assert.Error(t, err) {
		assert.Equal(t, "line 4: uneven number of digits in hex string", err.Error())
	}
	_, err = gyp.ParseString(`
	rule UNEVEN_HEX_STRING {
		strings:
			$s1 = {12233}
		condition:
			all of them
	}`)
	if assert.Error(t, err) {
		assert.Equal(t, "line 4: uneven number of digits in hex string", err.Error())
	}
}

func TestNonAsciiCharacters(t *testing.T) {
	// Non-ascii characters are NOT accepted in text strings.
	_, err := gyp.ParseString(`
	rule NON_ASCII {
		strings:
			$s1 = "foo` + "\xe8" + `bar"
		condition:
			all of them
	}`)
	if assert.Error(t, err) {
		assert.Equal(t, `line 4: non-ascii character "\xe8"`, err.Error())
	}

	// Non-ascii characters are NOT accepted in regexps.
	_, err = gyp.ParseString(`
	rule NON_ASCII {
		strings:
			$s1 = /foo` + "\x03" + `bar/
		condition:
			all of them
	}`)
	if assert.Error(t, err) {
		assert.Equal(t, `line 4: non-ascii character "\x03"`, err.Error())
	}

	// Non-ascii characters are NOT accepted in argument to base64 modifier.
	_, err = gyp.ParseString(`
	rule NON_ASCII {
		strings:
			$s1 = "foo" base64("é")
		condition:
			all of them
	}`)
	if assert.Error(t, err) {
		assert.Equal(t, `line 4: non-ascii character "\xc3"`, err.Error())
	}

	// Non-ascii characters are NOT accepted in string literals.
	_, err = gyp.ParseString(`
	rule NON_ASCII {
		condition:
			"abc" != "ñbc"
	}`)
	if assert.Error(t, err) {
		assert.Equal(t, `line 4: non-ascii character "\xc3"`, err.Error())
	}

	// Non-ascii characters are NOT accepted in string literals.
	_, err = gyp.ParseString(`
	import "ñoño"
	rule NON_ASCII {
		condition:
			false
	}`)
	if assert.Error(t, err) {
		assert.Equal(t, `line 2: non-ascii character "\xc3"`, err.Error())
	}

	// Non-ascii characters are accepted in meta strings.
	_, err = gyp.ParseString(`
	rule NON_ASCII {
        meta:
			test = "foo` + "\xe8" + `bar"
		condition:
			false
	}`)
	assert.NoError(t, err)

	// Non-ascii characters are accepted in comments.
	_, err = gyp.ParseString(`
	rule NON_ASCII {
        // This is a comment with a non-ascii é character: ` + "\xe8" + `
		condition:
			false
	}`)
	assert.NoError(t, err)
}
