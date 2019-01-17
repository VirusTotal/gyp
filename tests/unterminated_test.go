package tests

import (
	"strings"
	"testing"
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
	unterminatedChecker(t, err)
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
	unterminatedChecker(t, err)
}

// util func for checking an expected error for the word "unterminated"
func unterminatedChecker(t *testing.T, err error) {
	if err == nil {
		t.Fatalf("Error should not have been nil")
	}
	if !strings.Contains(err.Error(), "unterminated") {
		t.Fatalf("Error other than unterminated string/regex: %s", err)
	}
}
