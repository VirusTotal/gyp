package parser

import (
	"fmt"
	"github.com/VirusTotal/gyp/ast"
	gyperror "github.com/VirusTotal/gyp/error"
	"io"
	"io/ioutil"
)

func init() {
	yrErrorVerbose = true
}

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

// setError sets the lexer error. The error message can be built by passing
// a format string and arguments as fmt.Sprintf. This function returns 1 as
// it's intended to be used by Parse as:
//   return lexer.setError(...)
// By returning 1 from Parse the parsing is aborted.
func (l *lexer) setError(code gyperror.Code, format string, a ...interface{}) int {
	l.err = gyperror.Error{
		Code:    code,
		Line:    l.scanner.Lineno,
		Message: fmt.Sprintf(format, a...),
	}
	return 1
}

// Helper function that casts a yrLexer interface to a lexer struct.
func asLexer(l yrLexer) *lexer {
	return l.(*lexer)
}
