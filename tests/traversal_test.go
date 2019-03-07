package tests

import (
	"bytes"
	"testing"

	"github.com/VirusTotal/gyp"

	"github.com/VirusTotal/gyp/ast"
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

func (t *testVisitor) PreOrderVisit(e *ast.Expression) {
	var b bytes.Buffer
	s := gyp.NewSerializer(&b)
	s.SerializeExpression(e)
	t.preOrderResults = append(t.preOrderResults, b.String())
}

func (t *testVisitor) PostOrderVisit(e *ast.Expression) {
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
		`)

	assert.NoError(t, err)

	v := newTestVisitor()

	for _, r := range rs.GetRules() {
		r.GetCondition().DepthFirstSearch(v)
	}

	assert.Equal(t, []string{
		"true",
		"foo or bar",
		"foo",
		"bar",
		"int64(3)",
		"3",
		"for all i in (1..filesize + 1) : (true)",
		"1",
		"filesize + 1",
		"filesize",
		"1",
		"true",
	}, v.preOrderResults)

	assert.Equal(t, []string{
		"true",
		"foo",
		"bar",
		"foo or bar",
		"3",
		"int64(3)",
		"1",
		"filesize",
		"1",
		"filesize + 1",
		"true",
		"for all i in (1..filesize + 1) : (true)",
	}, v.postOrderResults)

}
