// adapter.go provides an adapter for a flexgo lexer to work
// with a goyacc parser

package hex

import (
	"fmt"
	"io"
	"io/ioutil"

	"github.com/VirusTotal/gyp/ast"
	gyperror "github.com/VirusTotal/gyp/error"
)

func init() {
	hexErrorVerbose = true
}

// Parse parses an hex string in a YARA rule from the provided input source
func Parse(input io.Reader) (tokens []ast.HexToken, err error) {
	defer func() {
		if r := recover(); r != nil {
			if yaraError, ok := r.(gyperror.Error); ok {
				err = yaraError
			} else {
				err = gyperror.Error{
					Code:    gyperror.UnknownError,
					Message: fmt.Sprintf("%s", r),
				}
			}
		}
	}()

	lexer := lexer{
		scanner:   *NewScanner(),
		hexTokens: nil,
	}
	lexer.scanner.In = input
	lexer.scanner.Out = ioutil.Discard

	if result := hexParse(&lexer); result != 0 {
		err = lexer.err
	}

	return lexer.hexTokens, err
}

// Lexer is an adapter that fits the flexgo lexer ("Scanner") into goyacc
type lexer struct {
	scanner   Scanner
	insideOr  int
	err       gyperror.Error
	hexTokens []ast.HexToken
}

// Lex provides the interface expected by the goyacc parser.
// It sets the context's lval pointer (defined in the hex_lexer.l file)
// to the one passed as an argument so that the parser actions
// can make use of it.
func (l *lexer) Lex(lval *hexSymType) int {
	r := l.scanner.Lex()
	if r.Error.Code != 0 {
		r.Error.Line = l.scanner.Lineno
		panic(r.Error)
	}
	if r.Value != nil {
		*lval = *r.Value
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

// setError sets the lexer error. The error message can be built by passing
// a format string and arguments as fmt.Sprintf. This function returns 1 as
// it's intended to by used in hex_grammar.y as:
//   return lexer.setError(...)
// By returning 1 from the parser the parsing is aborted.
func (l *lexer) setError(code gyperror.Code, format string, a ...interface{}) int {
	l.err = gyperror.Error{
		Code:    code,
		Line:    l.scanner.Lineno,
		Message: fmt.Sprintf(format, a...),
	}
	return 1
}

// Helper function that casts a yrLexer interface to a lexer struct. This
// function is used in grammar.y.
func asLexer(l hexLexer) *lexer {
	return l.(*lexer)
}
