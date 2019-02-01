package tests

import (
	"testing"

	"github.com/VirusTotal/go-yara-parser"
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
	_, err := parseRuleStr(rs)
	if err == nil {
		t.Fatalf(`Parsing succeeded; should have failed`)
	} else if err.(yara.Error).Code != yara.DuplicateRuleError {
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
	ruleset, err := parseRuleStr(rs)
	if err != nil {
		t.Fatalf(`Failed to parse ruleset w/ duplicate metas: %s`, err)
	}

	const nrules = 1
	if l := len(ruleset.Rules); l != nrules {
		t.Fatalf(`Expected %d rules; found %d`, nrules, l)
	}

	var (
		rule  = ruleset.Rules[0]
		key   = "description"
		nvals = len(rule.Meta)
	)
	const expectedVals = 4

	if nvals != expectedVals {
		t.Fatalf(`Expected %d metas; found %d`, expectedVals, nvals)
	}

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
	_, err := parseRuleStr(rs)
	if err == nil {
		t.Fatalf(`Parsing succeeded; should have failed`)
	} else if err.(yara.Error).Code != yara.DuplicateStringError {
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
	_, err := parseRuleStr(rs)
	if err != nil {
		t.Fatalf(`Failed to parse: %s`, err.Error())
	}
}

func TestDuplicateTags(t *testing.T) {
	const rs = `rule dup : tag1 tag2 tag3 tag1 {
condition:
  true
}`
	_, err := parseRuleStr(rs)
	if err == nil {
		t.Fatalf(`Parsing succeeded; should have failed`)
	} else if err.(yara.Error).Code != yara.DuplicateTagError {
		t.Fatalf(`Unexpected error: "%s", expected DuplicateTagError`, err.Error())
	}
}
