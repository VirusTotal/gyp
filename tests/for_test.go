package tests

import "testing"

func TestForLoop(t *testing.T) {
	const rs = `rule FOR {
strings:
    $s1 = "abc"
condition:
    for any i in (1..#s1) :
    (
        @s1[i] > 20
    )
}`
	_, err := parseRuleStr(rs)
	if err != nil {
		t.Fatalf(`Parsing failed: %s`, err)
	}
}
