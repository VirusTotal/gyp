package ast

import (
	"fmt"
	"io"

	"github.com/VirusTotal/gyp/pb"
	"github.com/golang/protobuf/proto"
)

// Node is the interface implemented by all types of nodes in the AST.
type Node interface {
	// Writes the source of the node to a writer.
	WriteSource(io.Writer) error
	// Returns the node serialized as a protobuf.
	AsProto() proto.Message
	// Returns the node's children. The children are returned left to right,
	// if the node represents the operation A + B + C, the children will
	// appear as A, B, C.
	Children() []Node
}

// Group is a Node that encloses another Node in parenthesis.
type Group struct {
	Node
}

// LiteralInteger is a Node that represents an integer constant.
type LiteralInteger struct {
	Value int64
}

// LiteralFloat is a Node that represents a string constant.
type LiteralFloat struct {
	Value float64
}

// LiteralString is a Node that represents a string constant.
type LiteralString struct {
	Value string
}

// Minus is a Node that represents the unary minus operation.
type Minus struct {
	Node
}

// Not is a Node that represents the "not" operation.
type Not struct {
	Node
}

// BitwiseNot is a Node that represents the bitwise not operation.
type BitwiseNot struct {
	Node
}

// WriteSource writes the node's source into the writer w.
func (g *Group) WriteSource(w io.Writer) error {
	_, err := io.WriteString(w, "(")
	if err == nil {
		err = g.Node.WriteSource(w)
	}
	if err == nil {
		_, err = io.WriteString(w, ")")
	}
	return err
}

// WriteSource writes the node's source into the writer w.
func (l *LiteralInteger) WriteSource(w io.Writer) error {
	_, err := fmt.Fprint(w, l.Value)
	return err
}

// WriteSource writes the node's source into the writer w.
func (l *LiteralFloat) WriteSource(w io.Writer) error {
	_, err := fmt.Fprint(w, l.Value)
	return err
}

// WriteSource writes the node's source into the writer w.
func (l *LiteralString) WriteSource(w io.Writer) error {
	_, err := fmt.Fprint(w, l.Value)
	return err
}

// WriteSource writes the node's source into the writer w.
func (m *Minus) WriteSource(w io.Writer) error {
	_, err := io.WriteString(w, "-")
	if err == nil {
		err = m.Node.WriteSource(w)
	}
	return err
}

// WriteSource writes the node's source into the writer w.
func (n *Not) WriteSource(w io.Writer) error {
	_, err := io.WriteString(w, "not ")
	if err == nil {
		err = n.Node.WriteSource(w)
	}
	return err
}

// WriteSource writes the node's source into the writer w.
func (b *BitwiseNot) WriteSource(w io.Writer) error {
	_, err := io.WriteString(w, "~")
	if err == nil {
		err = b.Node.WriteSource(w)
	}
	return err
}

// Children returns an empty list of nodes as a literal never has children,
// this function is required anyways in order to satisfy the Node interface.
func (l *LiteralInteger) Children() []Node {
	return []Node{}
}

// Children returns an empty list of nodes as a literal never has children,
// this function is required anyways in order to satisfy the Node interface.
func (l *LiteralFloat) Children() []Node {
	return []Node{}
}

// Children returns an empty list of nodes as a literal never has children,
// this function is required anyways in order to satisfy the Node interface.
func (l *LiteralString) Children() []Node {
	return []Node{}
}

// AsProto returns the keyword serialized as a protobuf.
func (l *LiteralInteger) AsProto() proto.Message {
	return &pb.Expression{
		Expression: &pb.Expression_NumberValue{
			NumberValue: l.Value,
		},
	}
}

// AsProto returns the keyword serialized as a protobuf.
func (l *LiteralFloat) AsProto() proto.Message {
	return &pb.Expression{
		Expression: &pb.Expression_DoubleValue{
			DoubleValue: l.Value,
		},
	}
}

// AsProto returns the keyword serialized as a protobuf.
func (l *LiteralString) AsProto() proto.Message {
	return &pb.Expression{
		Expression: &pb.Expression_Text{
			Text: l.Value,
		},
	}
}

// AsProto returns the keyword serialized as a protobuf.
func (n *Not) AsProto() proto.Message {
	return &pb.Expression{
		Expression: &pb.Expression_NotExpression{
			NotExpression: n.Node.AsProto().(*pb.Expression),
		},
	}
}
