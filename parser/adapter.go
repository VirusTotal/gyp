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
		strings: make(map[string]bool),
		rules: make(map[string]bool),
		rule_wildcards: make(map[string]bool),
	}
	lexer.scanner.In = input
	lexer.scanner.Out = ioutil.Discard

	// yrParse is the function automatically generated by goyacc from grammar.y
	// this function expects an argument that implements the yrLexer interface
	// which consists in the Lex(lval *yrSymType) and Error(s string) methods.
	if result := yrParse(lexer); result != 0 {
		err = lexer.err
	}

	return lexer.ruleSet, err
}

// Lexer is an adapter that fits the flexgo lexer ("Scanner") into goyacc
type lexer struct {
	scanner Scanner
	err     gyperror.Error
	// This stores the compiled rules.
	ruleSet *ast.RuleSet
	// Used to collect the strings as they are parsed on a per-rule basis.
	// When the condition is parsed this is used as a lookup table to check
	// for undefined strings.
	strings map[string]bool
	// Used as a lookup for rule identifiers only.
	rules map[string]bool
	// Used as a lookup for rule identifiers with wildcards to check if
	// a rule is defined _AFTER_ a rule uses it in a wildcard expansion.
	rule_wildcards map[string]bool
}

// Lex provides the interface expected by the goyacc parser. This function is
// called by the parser for getting the next token from the lexer. It returns
// the token number, and copies the value associated to the token (if any) into
// the struct pointed by lval.
func (l *lexer) Lex(lval *yrSymType) int {
	// Ask the lexer for the next token.
	r := l.scanner.Lex()
	if r.Error.Code != 0 {
		r.Error.Line = l.scanner.Lineno
		panic(r.Error)
	}
	// If the token has an associated value, copy it into lval.
	if r.Value != nil {
		*lval = *r.Value
	}
	// Save the token's line number in lval.
	lval.lineno = r.Lineno
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
// This uses whatever the current line the scanner is on. If you want to use
// a specific line number use the setErrorWithLineNumber variant.
func (l *lexer) setError(code gyperror.Code, format string, a ...interface{}) int {
    return l.setErrorWithLineNumber(code, l.scanner.Lineno, format, a...)
}

// setErrorWithLineNumber sets the lexer error. The error message can be built
// by passing a format string and arguments as fmt.Sprintf. This function
// returns 1 as it's intended to be used by Parse as:
//   return lexer.setErrorWithLineNumber(...)
// By returning 1 from Parse the parsing is aborted.
func (l *lexer) setErrorWithLineNumber(code gyperror.Code, lineno int, format string, a ...interface{}) int {
	l.err = gyperror.Error{
		Code:    code,
		Line:    lineno,
		Message: fmt.Sprintf(format, a...),
	}
	return 1
}

// Helper function that casts a yrLexer interface to a lexer struct.
func asLexer(l yrLexer) *lexer {
	return l.(*lexer)
}
