package gyperror

import (
	"fmt"
	"strings"
)

type Code int

const (
	LexicalError Code = iota
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
)

type Error struct {
	Code
	Data string
}

func (e Error) Error() string {
	if msg, ok := errorMessages[e.Code]; ok {
		var b strings.Builder
		b.WriteString(msg)
		if e.Data != "" {
			b.WriteString(": ")
			b.WriteString(e.Data)
		}

		return b.String()
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
}
