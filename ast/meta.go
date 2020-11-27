package ast

import (
	"fmt"
	"github.com/VirusTotal/gyp/pb"
	"github.com/golang/protobuf/proto"
)

const (
	lowerhex = "0123456789abcdef"
)

func toASCII(s string) string {
	ascii := make([]byte, 0)
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\n':
			ascii = append(ascii, `\n`...)
		case s[i] == '\r':
			ascii = append(ascii, `\r`...)
		case s[i] == '\t':
			ascii = append(ascii, `\t`...)
		case s[i] >= 32 && s[i] < 127:
			ascii = append(ascii, s[i])
		default:
			ascii = append(ascii, `\x`...)
			ascii = append(ascii, lowerhex[s[i]>>4])
			ascii = append(ascii, lowerhex[s[i]&0xF])
		}
	}
	return string(ascii)
}

// Meta represents an entry in a rule's metadata section. Each entry is
// composed of a key and a value. The value can be either a string, an int64
// or a bool.
type Meta struct {
	Key   string
	Value interface{}
}

// String returns the string representation of a metadata entry.
func (m *Meta) String() string {
	// With %#v we print the Golang's representation of the value, which
	// happens to be the same in YARA. For values of string type we don't use
	// %#v because Golang produces strings with escape sequences that are not
	// supported by YARA, like \u00a0.
	if s, isString := m.Value.(string); isString {
		return fmt.Sprintf("%s = \"%s\"", m.Key, toASCII(s))
	}
	return fmt.Sprintf("%s = %#v", m.Key, m.Value)
}

// AsProto returns the meta serialized as a Meta protobuf.
func (m *Meta) AsProto() *pb.Meta {
	meta := &pb.Meta{Key: proto.String(m.Key)}
	switch v := m.Value.(type) {
	case int64:
		meta.Value = &pb.Meta_Number{Number: v}
	case bool:
		meta.Value = &pb.Meta_Boolean{Boolean: v}
	case string:
		meta.Value = &pb.Meta_Text{Text: v}
	default:
		panic(fmt.Sprintf(`unexpected meta type: "%T"`, v))
	}
	return meta
}
