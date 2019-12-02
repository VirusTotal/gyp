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
	xxErrorVerbose = true
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

	if result := xxParse(&lexer); result != 0 {
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
// It sets the global yylval pointer (defined in the lexer file)
// to the one passed as an argument so that the parser actions
// can make use of it.
func (l *lexer) Lex(lval *xxSymType) int {
	yylval = lval
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
// it's intended to by used in hex_grammar.py as:
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
func asLexer(l xxLexer) *lexer {
	return l.(*lexer)
}
