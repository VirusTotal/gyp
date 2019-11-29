package gyperror

import (
	"fmt"
)

type Code int

const (
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
	NonAsciiByteError
	InvalidJumpLengthError
	JumpTooLargeInsideAlternationError
	NegativeJumpError
	InvalidJumpRangeError
	UnboundedJumpInsideAlternationError
	InvalidCharInHexStringError
	NumberConversionError
	IntegerOverflowError
	InvalidStringModifierError
)

type Error struct {
	Code
	Message string
	Line    int
}

func (e Error) Error() string {
	return fmt.Sprintf("line %d: %s", e.Line, e.Message)
}
