package tests

import (
	"testing"

	"github.com/VirusTotal/go-yara-parser"
)

// TestUnterminatedString tests for a rule with an unterminated string
func TestUnterminatedString(t *testing.T) {
	const rs = `rule unterminated_string {
meta:
  description = "String missing a closing quote"
strings:
  $s1 = "abcdefg
condition:
  any of them
}`
	_, err := parseRuleStr(rs)
	if err == nil {
		t.Fatalf(`Parsing succeeded; should have failed`)
	}
	yaraErr, ok := err.(yara.Error)
	if !ok || yaraErr.Code != yara.UnterminatedStringError {
		t.Fatalf(`Unexpected error: "%s", expected UnterminatedStringError`, err)
	}
}

// TestUnterminatedRegex tests for a rule with an unterminated regex
func TestUnterminatedRegex(t *testing.T) {
	const rs = `rule unterminated_regex {
meta:
  description = "regex missing a closing slash"
strings:
  $r1 = /abcdefg
condition:
  any of them
}`
	_, err := parseRuleStr(rs)
	if err == nil {
		t.Fatalf(`Parsing succeeded; should have failed`)
	}
	yaraErr, ok := err.(yara.Error)
	if !ok || yaraErr.Code != yara.UnterminatedRegexError {
		t.Fatalf(`Unexpected error: "%s", expected UnterminatedRegexError`, err)
	}
}
