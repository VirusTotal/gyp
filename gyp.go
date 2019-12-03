/*
Package gyp provides a pure Go parser for YARA rules.

For example, you can parse YARA rules from a string:
	ruleset, err := gyp.ParseString("rule test { condition: true }")

Or from a io.Reader:
	ruleset, err := gyp.Parse(os.Stdin)

The rules can be written to source again:
	err := ruleset.WriteSource(os.Stdout)

Or you can iterate over the rules and inspect their attributes:
	for _, rule := ruleset.Rules {
		fmt.Println(rule.Identifier)
	}
*/
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
