package ast

import (
	"fmt"
	"github.com/VirusTotal/gyp/pb"
	"github.com/golang/protobuf/proto"
	"strconv"
)

// Meta represents an entry in a rule's metadata section. Each entry is
// composed of a key and a value. The value can be either a string, an int64
// or a bool. When value is a string it appears exactly as in the source code,
// escaped characters remain escaped.
type Meta struct {
	Key   string
	Value interface{}
}

// String returns the string representation of a metadata entry.
func (m *Meta) String() string {
	// With %#v we print the Golang's representation of the value, which
	// happens to be the same in YARA. For values of string type we simply
	// use the value as is, because the meta value is the string exactly as
	// it appears in the YARA source.
	if s, isString := m.Value.(string); isString {
		return fmt.Sprintf("%s = \"%s\"", m.Key, s)
	}
	return fmt.Sprintf("%s = %#v", m.Key, m.Value)
}

// UnescapedValue returns the metadata Value with any escape sequence replaced
// by the actual character that it represents.
func (m *Meta) UnescapedValue() string {
	unescaped, err := strconv.Unquote(fmt.Sprintf(`"%s"`, m.Value))
	if err != nil {
		panic(err)
	}
	return unescaped
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
