package ast

import (
	"fmt"
	"io"
	"strings"

	"github.com/VirusTotal/gyp/pb"
	"github.com/golang/protobuf/proto"
)

// Node is the interface implemented by all types of nodes in the AST.
type Node interface {
	// WriteSource writes the source of the node to a writer.
	WriteSource(io.Writer) error
	// Children returns the node's children. The children are returned left to
	// right, if the node represents the operation A + B + C, the children will
	// appear as A, B, C. The result can be nil if the Node does not have
	// children.
	Children() []Node
}

// Expression is the interface implemented by all expressions in the AST. Not
// all nodes are expressions, but all expressions are nodes. In general, an
// expression is a Node that can be used as an operand in some kind of operation.
type Expression interface {
	Node
	AsProto() *pb.Expression
}

// Keyword is a Node that represents a keyword.
type Keyword string

// Constants for existing keywords.
const (
	KeywordAll        Keyword = "all"
	KeywordAny        Keyword = "any"
	KeywordNone       Keyword = "none"
	KeywordEntrypoint Keyword = "entrypoint"
	KeywordFalse      Keyword = "false"
	KeywordFilesize   Keyword = "filesize"
	KeywordThem       Keyword = "them"
	KeywordTrue       Keyword = "true"
)

// Group is an Expression that encloses another Expression in parentheses.
type Group struct {
	Expression Expression
}

// LiteralInteger is an Expression that represents a literal integer.
type LiteralInteger struct {
	Value int64
}

// LiteralFloat is an Expression that represents a literal float.
type LiteralFloat struct {
	Value float64
}

// LiteralString is an Expression that represents a literal string.
type LiteralString struct {
	Value string
}

// RegexpModifiers are flags containing the modifiers for a LiteralRegexp.
type RegexpModifiers int

const (
	_ = iota
	// RegexpCaseInsensitive is the flag corresponding to the /i modifier in a
	// regular expression literal.
	RegexpCaseInsensitive RegexpModifiers = 1 << iota
	// RegexpDotAll is the flag corresponding to the /s modifier in a regular
	// expression literal.
	RegexpDotAll
)

// LiteralRegexp is an Expression that represents a literal regular expression,
// like for example /ab.*cd/.
type LiteralRegexp struct {
	Value     string
	Modifiers RegexpModifiers
}

// Minus is an Expression that represents the unary minus operation.
type Minus struct {
	Expression Expression
}

// Not is an Expression that represents the "not" operation.
type Not struct {
	Expression Expression
}

// Defined is an Expression that represents the "defined" operation.
type Defined struct {
	Expression Expression
}

// BitwiseNot is an Expression that represents the bitwise not operation.
type BitwiseNot struct {
	Expression Expression
}

// Range is a Node that represents an integer range. Example: (1..10).
type Range struct {
	Start Expression
	End   Expression
}

// Enum is a Node that represents an enumeration. Example: (1,2,3,4).
type Enum struct {
	Values []Expression
}

// Identifier is an Expression that represents an identifier.
type Identifier struct {
	Identifier string
}

// StringIdentifier is an Expression that represents a string identifier in
// the condition, like "$a". The "At" field is non-nil if the identifier comes
// accompanied by an "at" condition, like "$a at 100". Similarly, "In" is
// non-nil if the identifier is accompanied by an "in" condition, like
// "$a in (0..100)". Notice that the Identifier field doesn't contain the $
// prefix.
type StringIdentifier struct {
	Identifier string
	At         Expression
	In         *Range
}

// StringCount is an Expression that represents a string count operation, like
// "#a". Notice that the Identifier field doesn't contain the # prefix.
// "In" is non-nil if the identifier is accompanied by an "in" condition, like
// "#a in (0..100) == 2".
type StringCount struct {
	Identifier string
	In         *Range
}

// StringOffset is an Expression that represents a string offset operation, like
// "@a". The "Index" field is non-nil if the count operation is indexed, like
// in "@a[1]". Notice that the Identifier field doesn't contain the @ prefix.
type StringOffset struct {
	Identifier string
	Index      Expression
}

// StringLength is an Expression that represents a string length operation, like
// "!a". The "Index" field is non-nil if the count operation is indexed, like
// in "!a[1]". Notice that the Identifier field doesn't contain the ! prefix.
type StringLength struct {
	Identifier string
	Index      Expression
}

// FunctionCall is an Expression that represents a function call.
type FunctionCall struct {
	Callable  Expression
	Arguments []Expression
	Builtin   bool
}

// MemberAccess is an Expression that represents a member access operation (.). For
// example, in "foo.bar" we have a MemberAccess operation where Node is the
// "foo" identifier and the member is "bar".
type MemberAccess struct {
	Container Expression
	Member    string
}

// Subscripting is an Expression that represents an array subscripting operation ([]).
// For example, in "foo[1+2]" we have a Subscripting operation where Array is
// a Node representing the "foo" identifier and Index is another Node that
// represents the expression "1+2".
type Subscripting struct {
	Array Expression
	Index Expression
}

// Percentage is an Expression used in evaluating string sets. Example:
//   <expression>% of <string set>
type Percentage struct {
	Expression Expression
}

// ForIn is an Expression representing a "for in" loop. Example:
//   for <quantifier> <variables> in <iterator> : ( <condition> )
type ForIn struct {
	Quantifier Expression
	Variables  []string
	Iterator   Node
	Condition  Expression
}

// ForOf is an Expression representing a "for of" loop. Example:
//   for <quantifier> of <string_set> : ( <condition> )
type ForOf struct {
	Quantifier Expression
	Strings    Node
	Condition  Expression
}

// Of is an Expression representing a "of" operation. Example:
//   <quantifier> of <string_set>
//   <quantifier> of <string_set> in <range>
// If "In" is non-nil there is an "in" condition: 3 of them in (0..100)
type Of struct {
	Quantifier  Expression
	Strings     Node
	Rules       Node
	TextStrings []string
	In          *Range
}

// Operation is an Expression representing an operation with two or more operands,
// like "A or B", "A and B and C", "A + B + C", "A - B - C", etc. If there are
// more than two operands the operation is considered left-associative, it's ok
// to have a single operation for representing A - B - C, but for A - (B - C) we
// need two operations with two operands each.
type Operation struct {
	Operator OperatorType
	Operands []Expression
}

func (l *LiteralString) String() string {
	return fmt.Sprintf(`"%s"`, l.Value)
}

func (l *LiteralRegexp) String() string {
	var modifiers string
	if l.Modifiers&RegexpCaseInsensitive != 0 {
		modifiers += "i"
	}
	if l.Modifiers&RegexpDotAll != 0 {
		modifiers += "s"
	}
	return fmt.Sprintf("/%s/%s", l.Value, modifiers)
}

// WriteSource writes the keyword into the writer w.
func (k Keyword) WriteSource(w io.Writer) error {
	_, err := io.WriteString(w, string(k))
	return err
}

// WriteSource writes the node's source into the writer w.
func (g *Group) WriteSource(w io.Writer) error {
	_, err := io.WriteString(w, "(")
	if err == nil {
		err = g.Expression.WriteSource(w)
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
	_, err := fmt.Fprintf(w, "%f", l.Value)
	return err
}

// WriteSource writes the node's source into the writer w.
func (l *LiteralString) WriteSource(w io.Writer) error {
	_, err := io.WriteString(w, l.String())
	return err
}

// WriteSource writes the node's source into the writer w.
func (l *LiteralRegexp) WriteSource(w io.Writer) error {
	_, err := io.WriteString(w, l.String())
	return err
}

// WriteSource writes the node's source into the writer w.
func (m *Minus) WriteSource(w io.Writer) error {
	_, err := io.WriteString(w, "-")
	if err == nil {
		err = m.Expression.WriteSource(w)
	}
	return err
}

// WriteSource writes the node's source into the writer w.
func (d *Defined) WriteSource(w io.Writer) error {
	_, err := io.WriteString(w, "defined ")
	if err == nil {
		err = d.Expression.WriteSource(w)
	}
	return err
}

// WriteSource writes the node's source into the writer w.
func (n *Not) WriteSource(w io.Writer) error {
	_, err := io.WriteString(w, "not ")
	if err == nil {
		err = n.Expression.WriteSource(w)
	}
	return err
}

// WriteSource writes the node's source into the writer w.
func (b *BitwiseNot) WriteSource(w io.Writer) error {
	_, err := io.WriteString(w, "~")
	if err == nil {
		err = b.Expression.WriteSource(w)
	}
	return err
}

// WriteSource writes the node's source into the writer w.
func (r *Range) WriteSource(w io.Writer) error {
	_, err := io.WriteString(w, "(")
	if err == nil {
		err = r.Start.WriteSource(w)
	}
	if err == nil {
		_, err = io.WriteString(w, "..")
	}
	if err == nil {
		err = r.End.WriteSource(w)
	}
	if err == nil {
		_, err = io.WriteString(w, ")")
	}
	return err
}

// WriteSource writes the node's source into the writer w.
func (e *Enum) WriteSource(w io.Writer) error {
	_, err := io.WriteString(w, "(")
	for i, expr := range e.Values {
		err = expr.WriteSource(w)
		if err == nil && i < len(e.Values)-1 {
			_, err = io.WriteString(w, ", ")
		}
		if err != nil {
			return err
		}
	}
	if err == nil {
		_, err = io.WriteString(w, ")")
	}
	return err
}

// WriteSource writes the node's source into the writer w.
func (i *Identifier) WriteSource(w io.Writer) error {
	_, err := io.WriteString(w, i.Identifier)
	return err
}

// WriteSource writes the node's source into the writer w.
func (s *StringIdentifier) WriteSource(w io.Writer) error {
	_, err := io.WriteString(w, fmt.Sprintf("$%s", s.Identifier))
	if err == nil && s.At != nil {
		_, err = io.WriteString(w, " at ")
		if err == nil {
			err = s.At.WriteSource(w)
		}
	}
	if err == nil && s.In != nil {
		_, err = io.WriteString(w, " in ")
		if err == nil {
			err = s.In.WriteSource(w)
		}
	}
	return err
}

// WriteSource writes the node's source into the writer w.
func (s *StringCount) WriteSource(w io.Writer) error {
	_, err := io.WriteString(w, fmt.Sprintf("#%s", s.Identifier))
	if err == nil && s.In != nil {
		_, err = io.WriteString(w, " in ")
		if err == nil {
			err = s.In.WriteSource(w)
		}
	}
	return err
}

// WriteSource writes the node's source into the writer w.
func (s *StringOffset) WriteSource(w io.Writer) error {
	_, err := io.WriteString(w, fmt.Sprintf("@%s", s.Identifier))
	if err == nil && s.Index != nil {
		_, err = io.WriteString(w, "[")
	}
	if err == nil && s.Index != nil {
		err = s.Index.WriteSource(w)
	}
	if err == nil && s.Index != nil {
		_, err = io.WriteString(w, "]")
	}
	return err
}

// WriteSource writes the node's source into the writer w.
func (s *StringLength) WriteSource(w io.Writer) error {
	_, err := io.WriteString(w, fmt.Sprintf("!%s", s.Identifier))
	if err == nil && s.Index != nil {
		_, err = io.WriteString(w, "[")
	}
	if err == nil && s.Index != nil {
		err = s.Index.WriteSource(w)
	}
	if err == nil && s.Index != nil {
		_, err = io.WriteString(w, "]")
	}
	return err
}

// WriteSource writes the node's source into the writer w.
func (f *FunctionCall) WriteSource(w io.Writer) error {
	err := f.Callable.WriteSource(w)
	if err == nil {
		_, err = io.WriteString(w, "(")
	}
	if err == nil {
		for i, arg := range f.Arguments {
			err = arg.WriteSource(w)
			// The comma is written after all arguments except the last one.
			if err == nil && i < len(f.Arguments)-1 {
				_, err = io.WriteString(w, ", ")
			}
		}
	}
	if err == nil {
		_, err = io.WriteString(w, ")")
	}
	return err
}

// WriteSource writes the node's source into the writer w.
func (m *MemberAccess) WriteSource(w io.Writer) error {
	err := m.Container.WriteSource(w)
	if err == nil {
		_, err = io.WriteString(w, ".")
	}
	if err == nil {
		_, err = io.WriteString(w, m.Member)
	}
	return err
}

// WriteSource writes the node's source into the writer w.
func (s *Subscripting) WriteSource(w io.Writer) error {
	err := s.Array.WriteSource(w)
	if err == nil {
		_, err = io.WriteString(w, "[")
	}
	if err == nil {
		err = s.Index.WriteSource(w)
	}
	if err == nil {
		_, err = io.WriteString(w, "]")
	}
	return err
}

// WriteSource writes the node's source into the writer w.
func (f *ForIn) WriteSource(w io.Writer) error {
	_, err := io.WriteString(w, "for ")
	if err == nil {
		err = f.Quantifier.WriteSource(w)
	}
	if err == nil {
		_, err = io.WriteString(w,
			fmt.Sprintf(" %s in ", strings.Join(f.Variables, ",")))
	}
	if err == nil {
		err = f.Iterator.WriteSource(w)
	}
	if err == nil {
		_, err = io.WriteString(w, " : (")
	}
	if err == nil {
		err = f.Condition.WriteSource(w)
	}
	if err == nil {
		_, err = io.WriteString(w, ")")
	}
	return err
}

// WriteSource writes the node's source into the writer w.
func (f *ForOf) WriteSource(w io.Writer) error {
	_, err := io.WriteString(w, "for ")
	if err == nil {
		err = f.Quantifier.WriteSource(w)
	}
	if err == nil {
		_, err = io.WriteString(w, " of ")
	}
	if err == nil {
		err = f.Strings.WriteSource(w)
	}
	if err == nil {
		_, err = io.WriteString(w, " : (")
	}
	if err == nil {
		err = f.Condition.WriteSource(w)
	}
	if err == nil {
		_, err = io.WriteString(w, ")")
	}
	return err
}

// WriteSource writes the node's source into the writer w.
func (o *Of) WriteSource(w io.Writer) error {
	if (o.Strings == nil && o.Rules == nil) || (o.Strings != nil && o.Rules != nil) {
		panic("expecting one string set or rule set in \"of\"")
	}
	err := o.Quantifier.WriteSource(w)
	if err == nil {
		_, err = io.WriteString(w, " of ")
	}
	if err == nil && o.Strings != nil {
		err = o.Strings.WriteSource(w)
	}
	if err == nil && o.Rules != nil {
		err = o.Rules.WriteSource(w)
	}
	if err == nil && o.In != nil {
		_, err = io.WriteString(w, " in ")
		if err == nil {
			err = o.In.WriteSource(w)
		}
	}
	return err
}

// WriteSource writes the node's source into the writer w.
func (p *Percentage) WriteSource(w io.Writer) error {
	err := p.Expression.WriteSource(w)
	if err == nil {
		_, err = io.WriteString(w, "%")
	}
	return err
}

// WriteSource writes the operation into the writer w.
func (o *Operation) WriteSource(w io.Writer) error {
	if len(o.Operands) < 2 {
		panic("expecting two or more operands")
	}
	// N-ary operation, write the operands with the operator in-between.
	if err := o.Operands[0].WriteSource(w); err != nil {
		return err
	}
	for _, operand := range o.Operands[1:] {
		if _, err := fmt.Fprintf(w, " %s ", o.Operator); err != nil {
			return err
		}
		if err := operand.WriteSource(w); err != nil {
			return err
		}
	}
	return nil
}

// Children returns nil as a keyword never has children, this function is
// required anyways in order to satisfy the Node interface.
func (k Keyword) Children() []Node {
	return nil
}

// Children returns the group's children, which is the expression inside the
// group.
func (g *Group) Children() []Node {
	return []Node{g.Expression}
}

// Children returns the Node's children.
func (l *LiteralInteger) Children() []Node {
	return nil
}

// Children returns the Node's children.
func (l *LiteralFloat) Children() []Node {
	return nil
}

// Children returns the Node's children.
func (l *LiteralString) Children() []Node {
	return nil
}

// Children returns the Node's children.
func (l *LiteralRegexp) Children() []Node {
	return nil
}

// Children returns the Node's children.
func (i *Identifier) Children() []Node {
	return nil
}

// Children returns the Node's children.
func (r *Range) Children() []Node {
	return []Node{r.Start, r.End}
}

// Children returns the Node's children.
func (e *Enum) Children() []Node {
	nodes := make([]Node, len(e.Values))
	for i, v := range e.Values {
		nodes[i] = v
	}
	return nodes
}

// Children returns the Node's children.
func (s *StringIdentifier) Children() []Node {
	if s.At == nil && s.In == nil {
		return nil
	}
	children := make([]Node, 0)
	if s.At != nil {
		children = append(children, s.At)
	}
	if s.In != nil {
		children = append(children, s.In)
	}
	return children
}

// Children returns the Node's children.
func (s *StringCount) Children() []Node {
	if s.In != nil {
		return []Node{s.In}
	}
	return nil
}

// Children returns the Node's children.
func (s *StringOffset) Children() []Node {
	if s.Index != nil {
		return []Node{s.Index}
	}
	return nil
}

// Children returns the Node's children.
func (s *StringLength) Children() []Node {
	if s.Index != nil {
		return []Node{s.Index}
	}
	return nil
}

// Children returns the Node's children.
func (f *FunctionCall) Children() []Node {
	expressions := append([]Expression{f.Callable}, f.Arguments...)
	nodes := make([]Node, len(expressions))
	for i, e := range expressions {
		nodes[i] = e
	}
	return nodes
}

// Children returns the node's child nodes.
func (m *MemberAccess) Children() []Node {
	return []Node{m.Container}
}

// Children returns the node's child nodes.
func (s *Subscripting) Children() []Node {
	return []Node{s.Array, s.Index}
}

// Children returns the node's child nodes.
func (f *ForIn) Children() []Node {
	return []Node{f.Quantifier, f.Iterator, f.Condition}
}

// Children returns the node's child nodes.
func (f *ForOf) Children() []Node {
	return []Node{f.Quantifier, f.Strings, f.Condition}
}

// Children returns the node's child nodes.
func (o *Of) Children() []Node {
	// Because this node can have children that are exclusively rules or
	// strings we need to only add them if they are non-nil.
	nodes := []Node{o.Quantifier}
	if o.Rules != nil {
		nodes = append(nodes, o.Rules)
	}
	if o.Strings != nil {
		nodes = append(nodes, o.Strings)
	}
	return nodes
}

// Children returns the operation's children nodes.
func (o *Operation) Children() []Node {
	nodes := make([]Node, len(o.Operands))
	for i, o := range o.Operands {
		nodes[i] = o
	}
	return nodes
}

func (n *Not) Children() []Node {
	return []Node{n.Expression}
}

func (m *Minus) Children() []Node {
	return []Node{m.Expression}
}

func (b *BitwiseNot) Children() []Node {
	return []Node{b.Expression}
}

func (d *Defined) Children() []Node {
	return []Node{d.Expression}
}

func (p *Percentage) Children() []Node {
	return []Node{p.Expression}
}

// AsProto returns the Expression serialized as a pb.Expression.
func (k Keyword) AsProto() *pb.Expression {
	switch k {
	case KeywordTrue:
		return &pb.Expression{
			Expression: &pb.Expression_BoolValue{
				BoolValue: true,
			}}
	case KeywordFalse:
		return &pb.Expression{
			Expression: &pb.Expression_BoolValue{
				BoolValue: false,
			}}
	case KeywordEntrypoint:
		return &pb.Expression{
			Expression: &pb.Expression_Keyword{
				Keyword: pb.Keyword_ENTRYPOINT,
			}}
	case KeywordFilesize:
		return &pb.Expression{
			Expression: &pb.Expression_Keyword{
				Keyword: pb.Keyword_FILESIZE,
			}}
	default:
		panic(fmt.Sprintf(`unexpected keyword "%s"`, k))
	}
}

func (g *Group) AsProto() *pb.Expression {
	return g.Expression.AsProto()
}

// AsProto returns the Expression serialized as a pb.Expression.
func (l *LiteralInteger) AsProto() *pb.Expression {
	return &pb.Expression{
		Expression: &pb.Expression_NumberValue{
			NumberValue: l.Value,
		},
	}
}

// AsProto returns the Expression serialized as a pb.Expression.
func (l *LiteralFloat) AsProto() *pb.Expression {
	return &pb.Expression{
		Expression: &pb.Expression_DoubleValue{
			DoubleValue: l.Value,
		},
	}
}

// AsProto returns the Expression serialized as a pb.Expression.
func (l *LiteralString) AsProto() *pb.Expression {
	return &pb.Expression{
		Expression: &pb.Expression_Text{
			Text: l.Value,
		},
	}
}

// AsProto returns the Expression serialized as a pb.Expression.
func (l *LiteralRegexp) AsProto() *pb.Expression {
	return &pb.Expression{
		Expression: &pb.Expression_Regexp{
			Regexp: &pb.Regexp{
				Text: proto.String(l.Value),
				Modifiers: &pb.StringModifiers{
					S: proto.Bool(l.Modifiers&RegexpDotAll != 0),
					I: proto.Bool(l.Modifiers&RegexpCaseInsensitive != 0),
				},
			},
		},
	}
}

// AsProto returns the Expression serialized as a pb.Expression.
func (m *Minus) AsProto() *pb.Expression {
	return &pb.Expression{
		Expression: &pb.Expression_UnaryExpression{
			UnaryExpression: &pb.UnaryExpression{
				Operator:   pb.UnaryExpression_UNARY_MINUS.Enum(),
				Expression: m.Expression.AsProto(),
			},
		},
	}
}

// AsProto returns the Expression serialized as a pb.Expression.
func (d *Defined) AsProto() *pb.Expression {
	return &pb.Expression{
		Expression: &pb.Expression_UnaryExpression{
			UnaryExpression: &pb.UnaryExpression{
				Operator:   pb.UnaryExpression_DEFINED.Enum(),
				Expression: d.Expression.AsProto(),
			},
		},
	}
}

func (b *BitwiseNot) AsProto() *pb.Expression {
	return &pb.Expression{
		Expression: &pb.Expression_UnaryExpression{
			UnaryExpression: &pb.UnaryExpression{
				Operator:   pb.UnaryExpression_BITWISE_NOT.Enum(),
				Expression: b.Expression.AsProto(),
			},
		},
	}
}

// AsProto returns the Expression serialized as a pb.Expression.
func (n *Not) AsProto() *pb.Expression {
	return &pb.Expression{
		Expression: &pb.Expression_NotExpression{
			NotExpression: n.Expression.AsProto(),
		},
	}
}

// AsProto returns the node serialized as pb.Range.
func (r *Range) AsProto() *pb.Range {
	return &pb.Range{
		Start: r.Start.AsProto(),
		End:   r.End.AsProto(),
	}
}

// AsProto returns the node serialized as pb.Range.
func (e *Enum) AsProto() *pb.IntegerEnumeration {
	values := make([]*pb.Expression, len(e.Values))
	for i, v := range e.Values {
		values[i] = v.AsProto()
	}
	return &pb.IntegerEnumeration{
		Values: values,
	}
}

// AsProto returns the Expression serialized as a pb.Expression.
func (i *Identifier) AsProto() *pb.Expression {
	return &pb.Expression{
		Expression: &pb.Expression_Identifier{
			Identifier: &pb.Identifier{
				Items: []*pb.Identifier_IdentifierItem{
					&pb.Identifier_IdentifierItem{
						Item: &pb.Identifier_IdentifierItem_Identifier{
							Identifier: i.Identifier,
						},
					},
				},
			},
		},
	}
}

// AsProto returns the Expression serialized as a pb.Expression.
func (s *StringIdentifier) AsProto() *pb.Expression {
	expr := &pb.Expression{
		Expression: &pb.Expression_StringIdentifier{
			StringIdentifier: fmt.Sprintf("$%s", s.Identifier),
		},
	}
	if s.At != nil {
		expr = &pb.Expression{
			Expression: &pb.Expression_BinaryExpression{
				BinaryExpression: &pb.BinaryExpression{
					Operator: pb.BinaryExpression_AT.Enum(),
					Left:     expr,
					Right:    s.At.AsProto(),
				},
			},
		}
	}
	if s.In != nil {
		expr = &pb.Expression{
			Expression: &pb.Expression_BinaryExpression{
				BinaryExpression: &pb.BinaryExpression{
					Operator: pb.BinaryExpression_IN.Enum(),
					Left:     expr,
					Right: &pb.Expression{
						Expression: &pb.Expression_Range{
							Range: s.In.AsProto(),
						},
					},
				},
			},
		}
	}
	return expr
}

// AsProto returns the Expression serialized as a pb.Expression.
func (s *StringCount) AsProto() *pb.Expression {
	expr := &pb.Expression{
		Expression: &pb.Expression_StringCount{
			StringCount: fmt.Sprintf("#%s", s.Identifier),
		},
	}
	if s.In != nil {
		expr = &pb.Expression{
			Expression: &pb.Expression_BinaryExpression{
				BinaryExpression: &pb.BinaryExpression{
					Operator: pb.BinaryExpression_IN.Enum(),
					Left:     expr,
					Right: &pb.Expression{
						Expression: &pb.Expression_Range{
							Range: s.In.AsProto(),
						},
					},
				},
			},
		}
	}
	return expr
}

// AsProto returns the Expression serialized as a pb.Expression.
func (s *StringOffset) AsProto() *pb.Expression {
	var index *pb.Expression
	if s.Index != nil {
		index = s.Index.AsProto()
	}
	return &pb.Expression{
		Expression: &pb.Expression_StringOffset{
			StringOffset: &pb.StringOffset{
				StringIdentifier: proto.String(fmt.Sprintf("@%s", s.Identifier)),
				Index:            index,
			},
		},
	}
}

// AsProto returns the Expression serialized as a pb.Expression.
func (s *StringLength) AsProto() *pb.Expression {
	var index *pb.Expression
	if s.Index != nil {
		index = s.Index.AsProto()
	}
	return &pb.Expression{
		Expression: &pb.Expression_StringLength{
			StringLength: &pb.StringLength{
				StringIdentifier: proto.String(fmt.Sprintf("!%s", s.Identifier)),
				Index:            index,
			},
		},
	}
}

// AsProto returns the Expression serialized as a pb.Expression.
func (f *FunctionCall) AsProto() *pb.Expression {
	args := make([]*pb.Expression, len(f.Arguments))
	for i, arg := range f.Arguments {
		args[i] = arg.AsProto()
	}
	callable := f.Callable.AsProto()
	identifier := callable.GetIdentifier()
	identifier.Items = append(identifier.GetItems(), &pb.Identifier_IdentifierItem{
		Item: &pb.Identifier_IdentifierItem_Arguments{
			Arguments: &pb.Expressions{
				Terms: args,
			},
		},
	})
	return &pb.Expression{
		Expression: &pb.Expression_Identifier{
			Identifier: identifier,
		},
	}
}

// AsProto returns the Expression serialized as a pb.Expression.
func (m *MemberAccess) AsProto() *pb.Expression {
	expr := m.Container.AsProto()
	identifier := expr.GetIdentifier()
	identifier.Items = append(identifier.GetItems(), &pb.Identifier_IdentifierItem{
		Item: &pb.Identifier_IdentifierItem_Identifier{
			Identifier: m.Member,
		},
	})
	return &pb.Expression{
		Expression: &pb.Expression_Identifier{
			Identifier: identifier,
		},
	}
}

// AsProto returns the Expression serialized as a pb.Expression.
func (s *Subscripting) AsProto() *pb.Expression {
	identifier := s.Array.AsProto().GetIdentifier()
	identifier.Items = append(identifier.GetItems(), &pb.Identifier_IdentifierItem{
		Item: &pb.Identifier_IdentifierItem_Index{
			Index: s.Index.AsProto(),
		},
	})
	return &pb.Expression{
		Expression: &pb.Expression_Identifier{
			Identifier: identifier,
		},
	}
}

// AsProto returns the Expression serialized as a pb.Expression.
func (p *Percentage) AsProto() *pb.Expression {
	return &pb.Expression{
		Expression: &pb.Expression_PercentageExpression{
			PercentageExpression: &pb.Percentage{
				Expression: p.Expression.AsProto(),
			},
		},
	}
}

// AsProto returns the Expression serialized as a pb.Expression.
func (f *ForIn) AsProto() *pb.Expression {
	var iterator *pb.Iterator
	switch v := f.Iterator.(type) {
	case *Range:
		iterator = &pb.Iterator{
			Iterator: &pb.Iterator_IntegerSet{
				IntegerSet: &pb.IntegerSet{
					Set: &pb.IntegerSet_Range{
						Range: &pb.Range{
							Start: v.Start.AsProto(),
							End:   v.End.AsProto(),
						},
					},
				},
			},
		}
	case *Enum:
		iterator = &pb.Iterator{
			Iterator: &pb.Iterator_IntegerSet{
				IntegerSet: &pb.IntegerSet{
					Set: &pb.IntegerSet_IntegerEnumeration{
						IntegerEnumeration: v.AsProto(),
					},
				},
			},
		}
	case Expression:
		iterator = &pb.Iterator{
			Iterator: &pb.Iterator_Identifier{
				Identifier: v.AsProto().GetIdentifier(),
			},
		}
	}
	return &pb.Expression{
		Expression: &pb.Expression_ForInExpression{
			ForInExpression: &pb.ForInExpression{
				ForExpression: quantifierToProto(f.Quantifier),
				Identifiers:   f.Variables,
				Iterator:      iterator,
				Expression:    f.Condition.AsProto(),
			},
		},
	}
}

// AsProto returns the Expression serialized as a pb.Expression.
func (f *ForOf) AsProto() *pb.Expression {
	var s *pb.StringSet
	switch v := f.Strings.(type) {
	case *Enum:
		items := make([]*pb.StringEnumeration_StringEnumerationItem, len(v.Values))
		for i, item := range v.Values {
			identifier := item.(*StringIdentifier).Identifier
			items[i] = &pb.StringEnumeration_StringEnumerationItem{
				StringIdentifier: proto.String(fmt.Sprintf("$%s", identifier)),
				HasWildcard:      proto.Bool(strings.HasSuffix(identifier, "*")),
			}
		}
		s = &pb.StringSet{
			Set: &pb.StringSet_Strings{
				Strings: &pb.StringEnumeration{
					Items: items,
				},
			},
		}
	case Keyword:
		if v != KeywordThem {
			panic(fmt.Sprintf(`unexpected keyword "%s"`, v))
		}
		s = &pb.StringSet{
			Set: &pb.StringSet_Keyword{
				Keyword: pb.StringSetKeyword_THEM,
			},
		}
	}
	return &pb.Expression{
		Expression: &pb.Expression_ForOfExpression{
			ForOfExpression: &pb.ForOfExpression{
				ForExpression: quantifierToProto(f.Quantifier),
				StringSet:     s,
				Expression:    f.Condition.AsProto(),
			},
		},
	}
}

// AsProto returns the Expression serialized as a pb.Expression.
func (o *Of) AsProto() *pb.Expression {
	if (o.Strings == nil && o.Rules == nil) || (o.Strings != nil && o.Rules != nil) {
		panic("expecting one string set or rule set in \"of\"")
	}
	var s *pb.StringSet
	var rule_enumeration *pb.RuleEnumeration
	if o.Strings != nil {
		switch v := o.Strings.(type) {
		case *Enum:
			items := make([]*pb.StringEnumeration_StringEnumerationItem, len(v.Values))
			for i, item := range v.Values {
				identifier := item.(*StringIdentifier).Identifier
				items[i] = &pb.StringEnumeration_StringEnumerationItem{
					StringIdentifier: proto.String(fmt.Sprintf("$%s", identifier)),
					HasWildcard:      proto.Bool(strings.HasSuffix(identifier, "*")),
				}
			}
			s = &pb.StringSet{
				Set: &pb.StringSet_Strings{
					Strings: &pb.StringEnumeration{
						Items: items,
					},
				},
			}
		case Keyword:
			if v != KeywordThem {
				panic(fmt.Sprintf(`unexpected keyword "%s"`, v))
			}
			s = &pb.StringSet{
				Set: &pb.StringSet_Keyword{
					Keyword: pb.StringSetKeyword_THEM,
				},
			}
		}
	}
	if o.Rules != nil {
		switch v := o.Rules.(type) {
		case *Enum:
			items := make([]*pb.RuleEnumeration_RuleEnumerationItem, len(v.Values))
			for i, item := range v.Values {
				identifier := item.(*Identifier).Identifier
				items[i] = &pb.RuleEnumeration_RuleEnumerationItem{
					RuleIdentifier: proto.String(fmt.Sprintf("%s", identifier)),
					HasWildcard:    proto.Bool(strings.HasSuffix(identifier, "*")),
				}
			}
			rule_enumeration = &pb.RuleEnumeration{
				Items: items,
			}
		}
	}
	var r *pb.Range = nil
	if o.In != nil {
		r = &pb.Range{
			Start: o.In.Start.AsProto(),
			End:   o.In.End.AsProto(),
		}
	}
	return &pb.Expression{
		Expression: &pb.Expression_ForOfExpression{
			ForOfExpression: &pb.ForOfExpression{
				ForExpression:   quantifierToProto(o.Quantifier),
				StringSet:       s,
				Range:           r,
				RuleEnumeration: rule_enumeration,
			},
		},
	}
}

// AsProto returns the Expression serialized as a pb.Expression.
func (o *Operation) AsProto() *pb.Expression {
	terms := make([]*pb.Expression, len(o.Operands))
	for i, operand := range o.Operands {
		terms[i] = operand.AsProto()
	}
	var expr *pb.Expression
	switch op := o.Operator; op {
	case OpOr:
		expr = &pb.Expression{
			Expression: &pb.Expression_OrExpression{
				OrExpression: &pb.Expressions{Terms: terms}}}
	case OpAnd:
		expr = &pb.Expression{
			Expression: &pb.Expression_AndExpression{
				AndExpression: &pb.Expressions{Terms: terms}}}
	case OpAdd, OpSub, OpMul, OpDiv, OpMod, OpEqual, OpNotEqual,
		OpLessThan, OpGreaterThan, OpLessOrEqual, OpGreaterOrEqual,
		OpBitOr, OpBitAnd, OpBitXor, OpShiftLeft, OpShiftRight,
		OpContains, OpIContains, OpStartsWith, OpIStartsWith,
		OpEndsWith, OpIEndsWith, OpMatches, OpIEquals:
		expr = terms[0]
		for _, term := range terms[1:] {
			expr = &pb.Expression{
				Expression: &pb.Expression_BinaryExpression{
					BinaryExpression: &pb.BinaryExpression{
						Operator: astToPb[op].Enum(),
						Left:     expr,
						Right:    term,
					},
				},
			}
		}
	default:
		panic(fmt.Sprintf(`unexpected operator "%v"`, op))
	}
	return expr
}
