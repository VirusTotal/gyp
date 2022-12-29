package error

import (
	"fmt"
)

type Code int

const (
	_                 = iota
	UnknownError Code = iota
	LexicalError
	DuplicateRuleError
	DuplicateTagError
	DuplicateStringError
	DuplicateModifierError
	UnterminatedStringError
	IllegalEscapeSequenceError
	InvalidRegexModifierError
	UnterminatedRegexError
	InvalidJumpLengthError
	JumpTooLargeInsideAlternationError
	NegativeJumpError
	InvalidJumpRangeError
	UnboundedJumpInsideAlternationError
	InvalidCharInHexStringError
	NumberConversionError
	IntegerOverflowError
	InvalidStringModifierError
	UnevenNumberOfDigitsError
	InvalidAsciiError
	InvalidUTF8Error
	UndefinedStringIdentifierError
	UndefinedRuleIdentifierError
	InvalidValueError
)

type Error struct {
	Code
	Message string
	Line    int
}

func (e Error) Error() string {
	return fmt.Sprintf("line %d: %s", e.Line, e.Message)
}
