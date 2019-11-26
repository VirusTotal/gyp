package tests

import (
	"io"
	"os"
	"testing"

	"github.com/VirusTotal/gyp"
	"github.com/VirusTotal/gyp/pb"
	"github.com/stretchr/testify/assert"
)

// These are just utilities

func openTestFile(t *testing.T, fname string) io.Reader {
	f, err := os.Open(fname)
	assert.NoError(t, err, `Couldn't open file "%s"`, fname)
	return f
}

func parseTestFile(t *testing.T, fname string) (*pb.RuleSet, error) {
	f := openTestFile(t, fname)
	return gyp.Parse(f)
}
