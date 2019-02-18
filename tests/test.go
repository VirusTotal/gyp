package tests

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/VirusTotal/gyp"
	"github.com/VirusTotal/gyp/ast"
)

// These are just utilities

func openTestFile(t *testing.T, fname string) io.Reader {
	f, err := os.Open(fname)
	if err != nil {
		t.Fatalf(`Couldn't open file "%s"`, fname)
	}
	return f
}

func parseTestFile(t *testing.T, fname string) (ast.RuleSet, error) {
	f := openTestFile(t, fname)
	return gyp.Parse(f)
}

func parseRuleStr(s string) (ast.RuleSet, error) {
	buf := bytes.NewBufferString(s)
	return gyp.Parse(buf)
}
