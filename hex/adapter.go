// adapter.go provides an adapter for a flexgo lexer to work
// with a goyacc parser

package hex

import (
	"fmt"
	"io"
	"io/ioutil"

	"github.com/VirusTotal/gyp/pb"
	"github.com/VirusTotal/gyp/error"
)

var lexicalError gyperror.Error

func init() {
	xxErrorVerbose = true
}

// Parse parses an hex string in a YARA rule from the provided input source
func Parse(input io.Reader) (hexstr pb.HexTokens, err error) {
	defer func() {
		if r := recover(); r != nil {
			if yaraError, ok := r.(gyperror.Error); ok {
				err = yaraError
			} else {
				err = gyperror.Error{
					Code: gyperror.UnknownError,
					Message: fmt.Sprintf("%s", r),
				}
			}
		}
	}()

	// "Reset" the global ParsedHexString
	ParsedHexString = pb.HexTokens{}

	lexer := Lexer{
		lexer: *NewScanner(),
	}
	lexer.lexer.In = input
	lexer.lexer.Out = ioutil.Discard

	if result := xxParse(&lexer); result != 0 {
		err = lexicalError
	}

	hexstr = ParsedHexString

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
func (l *Lexer) Error(e string) {
	lexicalError = gyperror.Error{
		Code: gyperror.LexicalError,
		Line: l.lexer.Lineno,
		Message: e,
	}
}
