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
	Data string
}

func (e Error) Error() string {
	if msg, ok := errorMessages[e.Code]; ok {
		if e.Data == "" {
			return msg
		}
		return fmt.Sprintf("%s: %s", msg, e.Data)
	}

	return fmt.Sprintf("unknown error: %d", e.Code)
}

var errorMessages = map[Code]string{
	LexicalError:                        "lexical error",
	DuplicateRuleError:                  "duplicate rule",
	DuplicateTagError:                   "duplicate tag",
	DuplicateStringError:                "duplicate string",
	UnterminatedStringError:             "unterminated string",
	IllegalEscapeSequenceError:          "illegal escape sequence",
	InvalidRegexModifierError:           "invalid regex modifier",
	UnterminatedRegexError:              "unterminated regular expression",
	NonAsciiByteError:                   "non-ASCII byte",
	InvalidJumpLengthError:              "invalid jump length",
	JumpTooLargeInsideAlternationError:  "jump too large inside alternation",
	NegativeJumpError:                   "negative jump",
	InvalidJumpRangeError:               "invalid jump range",
	UnboundedJumpInsideAlternationError: "unbounded jump inside alternation",
	InvalidCharInHexStringError:         "invalid char in hex string",
	NumberConversionError:               "number conversion error",
	IntegerOverflowError:                "integer overflow error",
	InvalidStringModifierError:          "invalid string modifier",
}
