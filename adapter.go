// adapter.go provides an adapter for a flexgo lexer to work
// with a goyacc parser

package gyp

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/VirusTotal/gyp/ast"
	gyperror "github.com/VirusTotal/gyp/error"
)

func init() {
	yrErrorVerbose = true
}

// Parse parses a YARA rule from the provided input source.
func Parse(input io.Reader) (rs *ast.RuleSet, err error) {
	defer func() {
		if r := recover(); r != nil {
			if yaraError, ok := r.(gyperror.Error); ok {
				err = yaraError
			} else {
				err = gyperror.Error{
					Code:    gyperror.UnknownError,
					Message: fmt.Sprintf("%v", r),
				}
			}
		}
	}()

	lexer := &lexer{
		scanner: *NewScanner(),
		ruleSet: &ast.RuleSet{
			Imports: make([]string, 0),
			Rules:   make([]*ast.Rule, 0),
		},
	}
	lexer.scanner.In = input
	lexer.scanner.Out = ioutil.Discard

	if result := yrParse(lexer); result != 0 {
		err = lexer.err
	}

	return lexer.ruleSet, err
}

// ParseString parses a YARA rule from the provided string.
func ParseString(s string) (*ast.RuleSet, error) {
	return Parse(bytes.NewBufferString(s))
}

// Lexer is an adapter that fits the flexgo lexer ("Scanner") into goyacc
type lexer struct {
	scanner Scanner
	err     gyperror.Error
	ruleSet *ast.RuleSet
}

// Lex provides the interface expected by the goyacc parser.
// It sets the context's lval pointer (defined in the lexer file)
// to the one passed as an argument so that the parser actions
// can make use of it.
func (l *lexer) Lex(lval *yrSymType) int {
	l.scanner.Context.lval = lval
	r := l.scanner.Lex()
	if r.Error.Code != 0 {
		r.Error.Line = l.scanner.Lineno
		panic(r.Error)
	}
	return r.Token
}

// Error satisfies the interface expected of the goyacc parser.
func (l *lexer) Error(msg string) {
	l.err = gyperror.Error{
		Code:    gyperror.LexicalError,
		Line:    l.scanner.Lineno,
		Message: msg,
	}
}

// SetError sets the lexer error. The error message can be built by passing
// a format string and arguments as fmt.Sprintf. This function returns 1 as
// it's intended to by used in grammar.py as:
//   return lexer.SetError(...)
// By returning 1 from the parser the parsing is aborted.
func (l *lexer) SetError(code gyperror.Code, format string, a ...interface{}) int {
	l.err = gyperror.Error{
		Code:    code,
		Line:    l.scanner.Lineno,
		Message: fmt.Sprintf(format, a...),
	}
	return 1
}

// Helper function that cast a yrLexer interface to a lexer struct. This
// function is used in in grammar.y.
func asLexer(l yrLexer) *lexer {
	return l.(*lexer)
}
