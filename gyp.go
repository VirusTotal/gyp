// adapter.go provides an adapter for a flexgo lexer to work
// with a goyacc parser

package gyp

import (
	"bytes"
	"io"

	"github.com/VirusTotal/gyp/ast"
	"github.com/VirusTotal/gyp/parser"
)

// Parse parses a YARA rule from the provided input source.
func Parse(input io.Reader) (rs *ast.RuleSet, err error) {
	return parser.Parse(input)
}

// ParseString parses a YARA rule from the provided string.
func ParseString(s string) (*ast.RuleSet, error) {
	return Parse(bytes.NewBufferString(s))
}
