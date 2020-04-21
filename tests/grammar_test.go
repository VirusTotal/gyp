package tests

import (
	"strings"
	"testing"

	"github.com/VirusTotal/gyp"
	"github.com/stretchr/testify/assert"
)

var testRules = `rule BASIC_BOOL {
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
    $s1 = "foo" ascii wide nocase fullword private base64 xor
    $s2 = "bar" xor(1)
    $s3 = "baz" xor(2-4)
    $s4 = "qux" base64("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
  condition:
    all of them
}

rule STRING_ESCAPED_CHARS {
  strings:
    $s1 = "C:\\Foo\"\\Bar\n"
  condition:
    $s1
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

func TestBase64AlphabetLength(t *testing.T) {
	_, err := gyp.ParseString(`
	rule BASE64 {
		strings:
			$foo = "foo" base64("baz")
	}`)
	assert.Error(t, err, "length of base64 alphabet must be 64")
}
