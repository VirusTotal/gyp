package tests

import (
	"testing"

	"github.com/VirusTotal/gyp"

	gyperror "github.com/VirusTotal/gyp/error"
	"github.com/stretchr/testify/assert"
)

func TestDuplicateRules(t *testing.T) {
	const rs = `rule dup {
condition:
  true
}

rule dup {
condition:
  false
}`
	_, err := gyp.ParseString(rs)
	assert.Error(t, err, `Parsing succeeded; should have failed`)

	yaraErr, ok := err.(gyperror.Error)
	if !ok || yaraErr.Code != gyperror.DuplicateRuleError {
		t.Fatalf(`Unexpected error: "%s", expected DuplicateRuleError`, err)
	}
}

func TestDuplicateMeta(t *testing.T) {
	const rs = `rule dup {
meta:
  description = "d1"
  description = "d2"
  description = 5
  description = "d1"
condition:
  true
}`
	ruleset, err := gyp.ParseString(rs)
	assert.NoError(t, err, `Failed to parse ruleset w/ duplicate metas: %s`, err)

	const nrules = 1
	assert.Len(t, ruleset.Rules, nrules)

	var (
		rule = ruleset.Rules[0]
		key  = "description"
	)

	const expectedVals = 4
	assert.Len(t, rule.Meta, expectedVals)

	for _, meta := range rule.Meta {
		if meta.GetKey() != key {
			t.Errorf(`Expected all meta keys to be "%s"; found "%s"`, key, meta.GetKey())
		}
	}
}

func TestDuplicateStrings(t *testing.T) {
	const rs = `rule dup {
strings:
  $s1 = "abc"
  $s1 = "def"
condition:
  any of them
}`
	_, err := gyp.ParseString(rs)
	assert.Error(t, err, `Parsing succeeded; should have failed`)

	yaraErr, ok := err.(gyperror.Error)
	if !ok || yaraErr.Code != gyperror.DuplicateStringError {
		t.Fatalf(`Unexpected error: "%s", expected DuplicateStringsError`, err)
	}
}

func TestDuplicateStringsAnonymous(t *testing.T) {
	const rs = `rule dup {
strings:
  $ = "abc"
  $ = "def"
condition:
  any of them
}`
	_, err := gyp.ParseString(rs)
	assert.NoError(t, err)
}

func TestDuplicateTags(t *testing.T) {
	const rs = `rule dup : tag1 tag2 tag3 tag1 {
condition:
  true
}`
	_, err := gyp.ParseString(rs)
	assert.Error(t, err, `Parsing succeeded; should have failed`)
	yaraErr, ok := err.(gyperror.Error)
	if !ok || yaraErr.Code != gyperror.DuplicateTagError {
		t.Fatalf(`Unexpected error: "%s", expected DuplicateTagError`, err.Error())
	}
}
