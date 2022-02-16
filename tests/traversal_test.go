package tests

import (
	"bytes"
	"testing"

	"github.com/VirusTotal/gyp"
	"github.com/VirusTotal/gyp/ast"
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

const rules = `
		rule rule_1 {
		condition:
			true
		}
		rule rule_2 {
		condition:
			foo or (bar)
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
		rule rule_10 {
		strings:
			$a = "foo"
			$b = "bar"
		condition:
			for any of ($a, $b) : (# < 10)
		}
		rule rule_11 {
		strings:
			$a = "foo"
			$b = "bar"
		condition:
			for all of ($a*) : ( @a > @b )
		}
		rule rule_12 {
		strings:
			$a = "foo*"
		condition:
			a and !a > 5
		}
		rule rule_13 {
		strings:
			$a = "foo"
		condition:
			#a in (0..100) == 2
		}
		rule rule_14 {
		strings:
			$a = "foo"
			$b = "bar"
		condition:
			10% of them
		}
		`

var preOrder = []string{
	// rule_1
	"true",

	// rule_2
	"foo or (bar)",
	"foo",
	"(bar)",
	"bar",

	// rule_3
	"int64(3)",
	"int64",
	"3",

	// rule_4
	"for all i in (1..filesize + 1) : (true)",
	"all",
	"(1..filesize + 1)",
	"1",
	"filesize + 1",
	"filesize",
	"1",
	"true",

	// rule_5
	"for any of ($a, $b) : (# < 10)",
	"any",
	"($a, $b)",
	"$a",
	"$b",
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
	"my_function",
	"1",
	"2",
	"3",

	// rule_9
	"for all i in my_function(\"foo\") : (i > 0)",
	"all",
	"my_function(\"foo\")",
	"my_function",
	"\"foo\"",
	"i > 0",
	"i",
	"0",

	// rule_10
	"for any of ($a, $b) : (# < 10)",
	"any",
	"($a, $b)",
	"$a",
	"$b",
	"# < 10",
	"#",
	"10",

	// rule_11
	"for all of ($a*) : (@a > @b)",
	"all",
	"($a*)",
	"$a*",
	"@a > @b",
	"@a",
	"@b",

	// rule_12
	"a and !a > 5",
	"a",
	"!a > 5",
	"!a",
	"5",

	// rule_13
	"#a in (0..100) == 2",
	"#a in (0..100)",
	"(0..100)",
	"0",
	"100",
	"2",

	// rule_14
	"10% of them",
	"10%",
	"10",
	"them",
}

var postOrder = []string{
	// rule_1
	"true",

	// rule_2
	"foo",
	"bar",
	"(bar)",
	"foo or (bar)",

	// rule_3
	"int64",
	"3",
	"int64(3)",

	// rule_4
	"all",
	"1",
	"filesize",
	"1",
	"filesize + 1",
	"(1..filesize + 1)",
	"true",
	"for all i in (1..filesize + 1) : (true)",

	// rule_5
	"any",
	"$a",
	"$b",
	"($a, $b)",
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
	"my_function",
	"1",
	"2",
	"3",
	"my_function(1, 2, 3)",

	// rule_9
	"all",
	"my_function",
	"\"foo\"",
	"my_function(\"foo\")",
	"i",
	"0",
	"i > 0",
	"for all i in my_function(\"foo\") : (i > 0)",

	// rule_10
	"any",
	"$a",
	"$b",
	"($a, $b)",
	"#",
	"10",
	"# < 10",
	"for any of ($a, $b) : (# < 10)",

	// rule_11
	"all",
	"$a*",
	"($a*)",
	"@a",
	"@b",
	"@a > @b",
	"for all of ($a*) : (@a > @b)",

	// rule_12
	"a",
	"!a",
	"5",
	"!a > 5",
	"a and !a > 5",

	// rule_13
	"0",
	"100",
	"(0..100)",
	"#a in (0..100)",
	"2",
	"#a in (0..100) == 2",

	// rule_14
	"10",
	"10%",
	"them",
	"10% of them",
}


type astVisitor struct {
	preOrderResults  []string
	postOrderResults []string
}

func newASTVisitor() *astVisitor {
	return &astVisitor{
		preOrderResults:  make([]string, 0),
		postOrderResults: make([]string, 0),
	}
}

func (t *astVisitor) PreOrderVisit(n ast.Node) {
	var b bytes.Buffer
	if err := n.WriteSource(&b); err == nil {
		t.preOrderResults = append(t.preOrderResults, b.String())
	}
}

func (t *astVisitor) PostOrderVisit(n ast.Node) {
	var b bytes.Buffer
	if err := n.WriteSource(&b); err == nil {
		t.postOrderResults = append(t.postOrderResults, b.String())
	}
}

func TestASTTraversal(t *testing.T) {
	rs, err := gyp.ParseString(rules)

	assert.NoError(t, err)

	v := newASTVisitor()
	for _, r := range rs.Rules {
		ast.DepthFirstSearch(r.Condition, v)
	}

	assert.Equal(t, preOrder, v.preOrderResults)
	assert.Equal(t, postOrder, v.postOrderResults)
}
