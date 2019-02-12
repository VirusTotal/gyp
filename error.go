package yara

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
	JumpTooLargeInsideAlternation
	NegativeJump
	InvalidJumpRange
	UnboundedJumpInsideAlternation
)

type Error struct {
	Code
	Data string
}

func newError(code Code, data string) error {
	if code == 0 {
		return nil
	}

	return Error{code, data}
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
	LexicalError:                   "lexical error",
	DuplicateRuleError:             "duplicate rule",
	DuplicateTagError:              "duplicate tag",
	DuplicateStringError:           "duplicate string",
	UnterminatedStringError:        "unterminated string",
	IllegalEscapeSequenceError:     "illegal escape sequence",
	InvalidRegexModifierError:      "invalid regex modifier",
	UnterminatedRegexError:         "unterminated regular expression",
	NonAsciiByteError:              "non-ASCII byte",
	InvalidJumpLengthError:         "invalid jump length",
	JumpTooLargeInsideAlternation:  "jump too large inside alternation",
	NegativeJump:                   "negative jump",
	InvalidJumpRange:               "invalid jump range",
	UnboundedJumpInsideAlternation: "unbounded jump inside alternation",
}
