package ast

import (
	"fmt"
	"io"
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
	GetIdentifier() string
	GetLineNo() int
}

// BaseString is a structure that contains the fields that are common to all
// types of strings. This structure is embedded in TextString, HexString and
// RegexpString.
type BaseString struct {
	// Identifier for the string, without the $ prefix.
	Identifier string
	// Line number where the string was defined.
	LineNo int
}

// TextString describes a YARA text string.
type TextString struct {
	BaseString
	// Value contains the string exactly as it appears in the YARA rule. Escape
	// sequences remain escaped. See the UnescapedValue function.
	Value          string
	ASCII          bool
	Wide           bool
	Nocase         bool
	Fullword       bool
	Private        bool
	Base64         bool
	Base64Alphabet string
	Xor            bool
	XorMin         int32
	XorMax         int32
}

// RegexpString describes a YARA regexp.
type RegexpString struct {
	BaseString
	// Value contains the string exactly as it appears in the YARA rule. Escape
	// sequences remain escaped. See the UnescapeValue function.
	Regexp   *LiteralRegexp
	ASCII    bool
	Wide     bool
	Nocase   bool
	Fullword bool
	Private  bool
}

// HexString describes a YARA hex string. Hex strings have an identifier and
// a sequence of tokens that conform the abstract syntax tree for the hex
// string. Each token can be any of the following types:
//   HexBytes: Represents a sequence of bytes, possibly masked, like:
//      01 02 03,  34 ?? A1 F? 03 ?3
//   HexJump: Represents a jump in the hex string, like:
//      [21], [0-100]
//   HexOr: Represents an alternative, like:
//      (A|B), (A|B|C)
//
type HexString struct {
	BaseString
	Tokens  HexTokens
	Private bool
}

// HexToken is the interface implemented by all types of token
type HexToken interface {
	Node
}

// HexTokens is a sequence of tokens.
type HexTokens []HexToken

// HexJump is an HexToken that represents a jump in the hex string, like for
// example the [10-20] jump in {01 02 [10-20] 03 04}. If End is 0, it means
// infinite, the jump [20-] has Start=20 and End=0.
type HexJump struct {
	Start int
	End   int
}

// HexBytes is an HexToken that represents a byte sequence. The bytes are
// stored in Bytes, while Masks contains a nibble-wise mask for each of the
// bytes (both arrays have the same length). Possible masks are:
// 00 -> Full wildcard, the corresponding byte is ignored (??).
// 0F -> The higher nibble is ignored (?X)
// F0 -> The lower nibble is ignored (X?)
// FF -> No wildcard at all.
type HexBytes struct {
	Bytes []byte
	Masks []byte
}

// HexOr is an HexToken that represents an alternative in the hex string, like
// the (03 04 | 05 06) alternative in { 01 02 (03 04 | 05 06) 07 08 }. Each
// item in Alternatives corresponds to an alternative.
type HexOr struct {
	Alternatives HexTokens
}

// UnescapedValue returns the string's Value with any escape sequence replaced
// by the actual character that it represents.
func (t *TextString) UnescapedValue() string {
	unescaped, err := strconv.Unquote(fmt.Sprintf(`"%s"`, t.Value))
	if err != nil {
		panic(err)
	}
	return unescaped
}

// Children returns the Node's children.
func (h *HexJump) Children() []Node {
	return []Node{}
}

// Children returns the Node's children.
func (h *HexBytes) Children() []Node {
	return []Node{}
}

// Children returns the Node's children.
func (h HexTokens) Children() []Node {
	return []Node{}
}

// Children returns the Node's children.
func (h *HexOr) Children() []Node {
	nodes := make([]Node, len(h.Alternatives))
	for i, a := range h.Alternatives {
		nodes[i] = a
	}
	return nodes
}

func (s *BaseString) GetIdentifier() string {
	return s.Identifier
}

func (s *BaseString) GetLineNo() int {
	return s.LineNo
}

func (t *TextString) String() string {
	var b strings.Builder
	t.WriteSource(&b)
	return b.String()
}

func (r *RegexpString) String() string {
	var b strings.Builder
	r.WriteSource(&b)
	return b.String()
}

func (h *HexString) String() string {
	var b strings.Builder
	h.WriteSource(&b)
	return b.String()
}

// WriteSource writes the node's source into the writer w.
func (t *TextString) WriteSource(w io.Writer) error {
	_, err := io.WriteString(w, fmt.Sprintf("$%s", t.Identifier))
	if err == nil {
		_, err = io.WriteString(w, " = ")
	}
	if err == nil {
		_, err = io.WriteString(w, fmt.Sprintf(`"%s"`, t.Value))
	}
	if err == nil && t.ASCII {
		_, err = io.WriteString(w, " ascii")
	}
	if err == nil && t.Wide {
		_, err = io.WriteString(w, " wide")
	}
	if err == nil && t.Nocase {
		_, err = io.WriteString(w, " nocase")
	}
	if err == nil && t.Fullword {
		_, err = io.WriteString(w, " fullword")
	}
	if err == nil && t.Private {
		_, err = io.WriteString(w, " private")
	}
	if err == nil && t.Base64 {
		if _, err = io.WriteString(w, " base64"); err == nil && t.Base64Alphabet != "" {
			_, err = io.WriteString(w, fmt.Sprintf("(\"%s\")", t.Base64Alphabet))
		}
	}
	if err == nil && t.Xor {
		if t.XorMin == 0 && t.XorMax == 255 {
			_, err = io.WriteString(w, " xor")
		} else if t.XorMin == t.XorMax {
			_, err = io.WriteString(w, fmt.Sprintf(" xor(%d)", t.XorMin))
		} else {
			_, err = io.WriteString(w, fmt.Sprintf(" xor(%d-%d)", t.XorMin, t.XorMax))
		}
	}
	return err
}

// WriteSource writes the node's source into the writer w.
func (r *RegexpString) WriteSource(w io.Writer) (err error) {
	if _, err = io.WriteString(w, fmt.Sprintf("$%s", r.Identifier)); err != nil {
		return err
	}
	if _, err = io.WriteString(w, " = "); err != nil {
		return err
	}
	if err = r.Regexp.WriteSource(w); err != nil {
		return err
	}
	if r.ASCII {
		if _, err = io.WriteString(w, " ascii"); err != nil {
			return err
		}
	}
	if r.Wide {
		if _, err = io.WriteString(w, " wide"); err != nil {
			return err
		}
	}
	if r.Nocase {
		if _, err = io.WriteString(w, " nocase"); err != nil {
			return err
		}
	}
	if r.Fullword {
		if _, err = io.WriteString(w, " fullword"); err != nil {
			return err
		}
	}
	if r.Private {
		_, err = io.WriteString(w, " private")
	}
	return err
}

// WriteSource writes the node's source into the writer w.
func (h *HexString) WriteSource(w io.Writer) (err error) {
	if _, err = io.WriteString(w, fmt.Sprintf("$%s", h.Identifier)); err != nil {
		return err
	}
	if _, err = io.WriteString(w, " = { "); err != nil {
		return err
	}
	if err = h.Tokens.WriteSource(w); err != nil {
		return err
	}
	if _, err = io.WriteString(w, "}"); err != nil {
		return err
	}
	if h.Private {
		_, err = io.WriteString(w, " private")
	}
	return err
}

// WriteSource writes the node's source into the writer w.
func (h *HexBytes) WriteSource(w io.Writer) error {
	for i, b := range h.Bytes {
		var s string
		switch mask := h.Masks[i]; mask {
		case 0x00:
			s = "?? "
		case 0x0F:
			s = fmt.Sprintf("%02X ", b)
			s = "?" + s[1:]
		case 0xF0:
			s = fmt.Sprintf("%02X", b)
			s = s[:1] + "? "
		case 0xFF:
			s = fmt.Sprintf("%02X ", b)
		default:
			panic(fmt.Errorf(`unexpected byte mask: "%0X"`, mask))
		}
		if _, err := io.WriteString(w, s); err != nil {
			return err
		}
	}
	return nil
}

// WriteSource writes the node's source into the writer w.
func (h HexTokens) WriteSource(w io.Writer) error {
	for _, t := range h {
		if err := t.WriteSource(w); err != nil {
			return err
		}
	}
	return nil
}

// WriteSource writes the node's source into the writer w.
func (h *HexJump) WriteSource(w io.Writer) (err error) {
	if h.Start == 0 && h.End == 0 {
		_, err = fmt.Fprintf(w, "[-] ")
	} else if h.Start == h.End {
		_, err = fmt.Fprintf(w, "[%d] ", h.Start)
	} else if h.Start == 0 {
		_, err = fmt.Fprintf(w, "[0-%d] ", h.End)
	} else if h.End == 0 {
		_, err = fmt.Fprintf(w, "[%d-] ", h.Start)
	} else {
		_, err = fmt.Fprintf(w, "[%d-%d] ", h.Start, h.End)
	}
	return err
}

// WriteSource writes the node's source into the writer w.
func (h *HexOr) WriteSource(w io.Writer) error {
	if _, err := io.WriteString(w, "( "); err != nil {
		return err
	}
	for i, a := range h.Alternatives {
		if err := a.WriteSource(w); err != nil {
			return err
		}
		if i < len(h.Alternatives)-1 {
			if _, err := io.WriteString(w, "| "); err != nil {
				return err
			}
		}
	}
	_, err := io.WriteString(w, ") ")
	return err
}

// AsProto returns the string serialized as pb.String.
func (t *TextString) AsProto() *pb.String {
	modifiers := &pb.StringModifiers{
		Ascii:          proto.Bool(t.ASCII),
		Wide:           proto.Bool(t.Wide),
		Fullword:       proto.Bool(t.Fullword),
		Nocase:         proto.Bool(t.Nocase),
		Private:        proto.Bool(t.Private),
		Xor:            proto.Bool(t.Xor),
		XorMin:         proto.Int32(t.XorMin),
		XorMax:         proto.Int32(t.XorMax),
		Base64:         proto.Bool(t.Base64),
		Base64Alphabet: proto.String(t.Base64Alphabet),
	}
	return &pb.String{
		Id: proto.String(fmt.Sprintf("$%s", t.Identifier)),
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
		Id: proto.String(fmt.Sprintf("$%s", r.Identifier)),
		Value: &pb.String_Regexp{
			Regexp: regexp,
		},
	}
}

// AsProto returns the string serialized as pb.String.
func (h *HexString) AsProto() *pb.String {
	return &pb.String{
		Id: proto.String(fmt.Sprintf("$%s", h.Identifier)),
		Value: &pb.String_Hex{
			Hex: h.Tokens.AsProto(),
		},
	}
}

// AsProto returns the Node serialized as pb.String.
func (h *HexBytes) AsProto() *pb.BytesSequence {
	return &pb.BytesSequence{
		Value: h.Bytes,
		Mask:  h.Masks,
	}
}

// AsProto returns the Node serialized as pb.String.
func (h *HexJump) AsProto() *pb.Jump {
	var start *int64
	var end *int64
	if h.Start > 0 {
		start = proto.Int64(int64(h.Start))
	}
	if h.End > 0 {
		end = proto.Int64(int64(h.End))
	}
	return &pb.Jump{
		Start: start,
		End:   end,
	}
}

// AsProto returns the Node serialized as pb.String.
func (h *HexOr) AsProto() *pb.HexAlternative {
	tokens := make([]*pb.HexTokens, len(h.Alternatives))
	for i, a := range h.Alternatives {
		tokens[i] = a.(HexTokens).AsProto()
	}
	return &pb.HexAlternative{
		Tokens: tokens,
	}
}

// AsProto returns the tokens serialized as a pb.HexTokens.
func (h HexTokens) AsProto() *pb.HexTokens {
	tokens := make([]*pb.HexToken, len(h))
	for i, t := range h {
		switch v := t.(type) {
		case *HexBytes:
			tokens[i] = &pb.HexToken{
				Value: &pb.HexToken_Sequence{
					Sequence: v.AsProto(),
				},
			}
		case *HexJump:
			tokens[i] = &pb.HexToken{
				Value: &pb.HexToken_Jump{
					Jump: v.AsProto(),
				},
			}
		case *HexOr:
			tokens[i] = &pb.HexToken{
				Value: &pb.HexToken_Alternative{
					Alternative: v.AsProto(),
				},
			}
		}

	}
	return &pb.HexTokens{Token: tokens}
}
