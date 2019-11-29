package ast

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/VirusTotal/gyp/pb"
	"github.com/golang/protobuf/proto"
)

// String is the interface implemented by the different types of strings that
// are supported by YARA (i.e: text strings, hex strings and regexps).
type String interface {
	fmt.Stringer
	AsProto() *pb.String
}

// TextString describes a YARA text string.
type TextString struct {
	Identifier string
	// Value contains the string exactly as it appears in the YARA rule. Escape
	// sequences remain escaped. See the UnescapeValue function.
	Value    string
	ASCII    bool
	Wide     bool
	Nocase   bool
	Fullword bool
	Private  bool
	Xor      bool
	XorMin   int32
	XorMax   int32
}

// RegexpString describes a YARA regexp.
type RegexpString struct {
	Identifier string
	// Value contains the string exactly as it appears in the YARA rule. Escape
	// sequences remain escaped. See the UnescapeValue function.
	Regexp   *LiteralRegexp
	ASCII    bool
	Wide     bool
	Nocase   bool
	Fullword bool
	Private  bool
}

// UnescapedValue retuns the string's Value with any escape sequence replaced
// by the actual character that it representt.
func (t *TextString) UnescapedValue() string {
	unescaped, err := strconv.Unquote(fmt.Sprintf(`"%s"`, t.Value))
	if err != nil {
		panic(err)
	}
	return unescaped
}

func (t *TextString) String() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf(`%s = "%s"`, t.Identifier, t.Value))
	if t.ASCII {
		b.WriteString(" ascii")
	}
	if t.Wide {
		b.WriteString(" wide")
	}
	if t.Nocase {
		b.WriteString(" nocase")
	}
	if t.Fullword {
		b.WriteString(" fullword")
	}
	if t.Private {
		b.WriteString(" private")
	}
	if t.Xor {
		if t.XorMin == 0 && t.XorMax == 255 {
			b.WriteString(" xor")
		} else if t.XorMin == t.XorMax {
			b.WriteString(fmt.Sprintf(" xor(%d)", t.XorMin))
		} else {
			b.WriteString(fmt.Sprintf(" xor(%d-%d)", t.XorMin, t.XorMax))
		}
	}
	return b.String()
}

func (r *RegexpString) String() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf(`%s = %s`, r.Identifier, r.Regexp))
	if r.ASCII {
		b.WriteString(" ascii")
	}
	if r.Wide {
		b.WriteString(" wide")
	}
	if r.Nocase {
		b.WriteString(" nocase")
	}
	if r.Fullword {
		b.WriteString(" fullword")
	}
	if r.Private {
		b.WriteString(" private")
	}
	return b.String()
}

// AsProto returns the string serialized as pb.String.
func (t *TextString) AsProto() *pb.String {
	modifiers := &pb.StringModifiers{
		Ascii:    proto.Bool(t.ASCII),
		Wide:     proto.Bool(t.Wide),
		Fullword: proto.Bool(t.Fullword),
		Nocase:   proto.Bool(t.Nocase),
		Private:  proto.Bool(t.Private),
		Xor:      proto.Bool(t.Xor),
		XorMin:   proto.Int32(t.XorMin),
		XorMax:   proto.Int32(t.XorMax),
	}
	return &pb.String{
		Id: proto.String(t.Identifier),
		Value: &pb.String_Text{
			Text: &pb.TextString{
				Text:      proto.String(t.UnescapedValue()),
				Modifiers: modifiers,
			},
		},
	}
}

// AsProto returns the string serialized as pb.String.
func (r *RegexpString) AsProto() *pb.String {
	regexp := r.Regexp.AsProto().GetRegexp()
	m := regexp.GetModifiers()
	m.Ascii = proto.Bool(r.ASCII)
	m.Wide = proto.Bool(r.Wide)
	m.Fullword = proto.Bool(r.Fullword)
	m.Nocase = proto.Bool(r.Nocase)
	m.Private = proto.Bool(r.Private)
	return &pb.String{
		Id: proto.String(r.Identifier),
		Value: &pb.String_Regexp{
			Regexp: regexp,
		},
	}
}
