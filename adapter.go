// adapter.go provides an adapter for a flexgo lexer to work
// with a goyacc parser

package gyp

import (
	"fmt"
	"io"
	"io/ioutil"

	"github.com/VirusTotal/gyp/ast"
	"github.com/VirusTotal/gyp/error"
)

var lexicalError gyperror.Error

func init() {
	xxErrorVerbose = true
}

// Parse parses a YARA rule from the provided input source
func Parse(input io.Reader) (rs ast.RuleSet, err error) {
	defer func() {
		if r := recover(); r != nil {
			if yaraError, ok := r.(gyperror.Error); ok {
				err = yaraError
			} else {
				panic(r)
			}
		}
	}()

	// "Reset" the global ParsedRuleset
	ParsedRuleset = ast.RuleSet{}

	lexer := Lexer{
		lexer: *NewScanner(),
	}
	lexer.lexer.In = input
	lexer.lexer.Out = ioutil.Discard

	if result := xxParse(&lexer); result != 0 {
		err = lexicalError
	}

	rs = ParsedRuleset

	return
}

// Lexer is an adapter that fits the flexgo lexer ("Scanner") into goyacc
type Lexer struct {
	lexer Scanner
}

// Lex provides the interface expected by the goyacc parser.
// It sets the global yylval pointer (defined in the lexer file)
// to the one passed as an argument so that the parser actions
// can make use of it.
func (l *Lexer) Lex(lval *xxSymType) int {
	yylval = lval
	return l.lexer.Lex().(int)
}

// Error satisfies the interface expected of the goyacc parser.
// Here, it simply writes the error to stdout.
func (l *Lexer) Error(e string) {
	lexicalError = gyperror.Error{
		Code: gyperror.LexicalError,
		Data: fmt.Sprintf(`@%d - "%s"`, l.lexer.Lineno, e),
	}
}
