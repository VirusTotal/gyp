package tests

import (
	"bytes"
	"testing"

	"github.com/VirusTotal/gyp"
	"github.com/VirusTotal/gyp/pb"
	"github.com/stretchr/testify/assert"
)

type testVisitor struct {
	s                *gyp.YaraSerializer
	preOrderResults  []string
	postOrderResults []string
}

func newTestVisitor() *testVisitor {
	return &testVisitor{
		preOrderResults:  make([]string, 0),
		postOrderResults: make([]string, 0),
	}
}

func (t *testVisitor) PreOrderVisit(e *pb.Expression) {
	var b bytes.Buffer
	s := gyp.NewSerializer(&b)
	s.SerializeExpression(e)
	t.preOrderResults = append(t.preOrderResults, b.String())
}

func (t *testVisitor) PostOrderVisit(e *pb.Expression) {
	var b bytes.Buffer
	s := gyp.NewSerializer(&b)
	s.SerializeExpression(e)
	t.postOrderResults = append(t.postOrderResults, b.String())
}

func TestTraversal(t *testing.T) {

	rs, err := gyp.ParseString(`
		rule rule_1 {
		condition:
			true
		}
		rule rule_2 {
		condition:
			foo or bar
		}
		rule rule_3 {
		condition:
			int64(3)
		}
		rule rule_4 {
		condition:
			for all i in (1..filesize + 1) : (true)
		}
		rule rule_5 {
		strings:
			$a = "foo"
			$b = "bar"
		condition:
			for any of ($a, $b) : (# < 10)
		}
		rule rule_6 {
		strings:
			$a = "foo"
		condition:
			@a[1 + 1] > 2
		}
		rule rule_7 {
			condition: not true
		}
		rule rule_8 {
			condition: my_function(1,2,3)
		}
		rule rule_9 {
			condition: for all i in my_function("foo") : ( i > 0)
		}
		`)

	assert.NoError(t, err)

	v := newTestVisitor()

	for _, r := range rs.AsProto().GetRules() {
		r.GetCondition().DepthFirstSearch(v)
	}

	assert.Equal(t, []string{
		// rule_1
		"true",

		// rule_2
		"foo or bar",
		"foo",
		"bar",

		// rule_3
		"int64(3)",
		"3",

		// rule_4
		"for all i in (1..filesize + 1) : (true)",
		"1",
		"filesize + 1",
		"filesize",
		"1",
		"true",

		// rule_5
		"for any of ($a, $b) : (# < 10)",
		"# < 10",
		"#",
		"10",

		// rule_6
		"@a[1 + 1] > 2",
		"@a[1 + 1]",
		"1 + 1",
		"1",
		"1",
		"2",

		// rule_7
		"not true",
		"true",

		// rule_8
		"my_function(1, 2, 3)",
		"1",
		"2",
		"3",

		// rule_9
		"for all i in my_function(\"foo\") : (i > 0)",
		"\"foo\"",
		"i > 0",
		"i",
		"0",
	}, v.preOrderResults)

	assert.Equal(t, []string{
		// rule_1
		"true",

		// rule_2
		"foo",
		"bar",
		"foo or bar",

		// rule_3
		"3",
		"int64(3)",

		// rule_4
		"1",
		"filesize",
		"1",
		"filesize + 1",
		"true",
		"for all i in (1..filesize + 1) : (true)",

		// rule_5
		"#",
		"10",
		"# < 10",
		"for any of ($a, $b) : (# < 10)",

		// rule_6
		"1",
		"1",
		"1 + 1",
		"@a[1 + 1]",
		"2",
		"@a[1 + 1] > 2",

		// rule_7
		"true",
		"not true",

		// rule_8
		"1",
		"2",
		"3",
		"my_function(1, 2, 3)",

		// rule_9
		"\"foo\"",
		"i",
		"0",
		"i > 0",
		"for all i in my_function(\"foo\") : (i > 0)",
	}, v.postOrderResults)

}
