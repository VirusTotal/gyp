package tests

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/VirusTotal/go-yara-parser"
)

// These are just utilities

func openTestFile(t *testing.T, fname string) io.Reader {
	f, err := os.Open(fname)
	if err != nil {
		t.Fatalf(`Couldn't open file "%s"`, fname)
	}
	return f
}

func parseTestFile(t *testing.T, fname string) (yara.RuleSet, error) {
	f := openTestFile(t, fname)
	return yara.Parse(f, os.Stderr)
}

func parseRuleStr(s string) (yara.RuleSet, error) {
	buf := bytes.NewBufferString(s)
	return yara.Parse(buf, os.Stderr)
}
