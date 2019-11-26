package ast

import (
	"fmt"
	"github.com/VirusTotal/gyp/pb"
	"github.com/golang/protobuf/proto"
	"io"
)

// OperatorType is the type of operators.
type OperatorType string

// Constants that represents operators.
const (
	OpOr             OperatorType = "or"
	OpAnd            OperatorType = "and"
	OpBitOr          OperatorType = "|"
	OpBitXor         OperatorType = "^"
	OpBitAnd         OperatorType = "&"
	OpEqual          OperatorType = "=="
	OpNotEqual       OperatorType = "!="
	OpLessThan       OperatorType = "<"
	OpGreaterThan    OperatorType = ">"
	OpLessOrEqual    OperatorType = "<="
	OpGreaterOrEqual OperatorType = ">="
	OpSub            OperatorType = "-"
	OpAdd            OperatorType = "+"
	OpMul            OperatorType = "*"
	OpDiv            OperatorType = "\\"
	OpMod            OperatorType = "%"
	OpShiftLeft      OperatorType = "<<"
	OpShiftRight     OperatorType = ">>"
)

// OpPrecedence is the operator precedence table.
var OpPrecedence = map[OperatorType]int{
	OpOr:             1,
	OpAnd:            2,
	OpBitOr:          3,
	OpBitXor:         4,
	OpBitAnd:         5,
	OpEqual:          6,
	OpNotEqual:       6,
	OpLessThan:       7,
	OpLessOrEqual:    7,
	OpGreaterThan:    7,
	OpGreaterOrEqual: 7,
	OpShiftLeft:      8,
	OpShiftRight:     8,
	OpAdd:            9,
	OpSub:            9,
	OpMul:            10,
	OpDiv:            10,
	OpMod:            10,
}

// OpMaxPrecedence is the maximum possible precedence. This also the precedence
// for unary operators "not", "~" and "-".
const OpMaxPrecedence = 11

// Operation describes an operation with one or more operands. For example:
// "not A", "A or B", "A and B and C", "A + B + C", "A - B - C", etc. If there
// are more than two operands the operation is considered left-associative,
// it's ok to have a single operation for representing A - B - C, but for
// A - (B - C) we need two operations with two operands each.
type Operation struct {
	Operator OperatorType
	Operands []Node
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

// Children returns the operation's children nodes.
func (o *Operation) Children() []Node {
	return o.Operands
}

// AsProto returns the keyword serialized as a protobuf.
func (o *Operation) AsProto() proto.Message {
	terms := make([]*pb.Expression, len(o.Operands))
	for i, operand := range o.Operands {
		terms[i] = operand.AsProto().(*pb.Expression)
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
	case OpAdd, OpSub:
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
	case OpEqual:
		expr = &pb.Expression{
			Expression: &pb.Expression_BinaryExpression{
				BinaryExpression: &pb.BinaryExpression{
					Operator: pb.BinaryExpression_EQ.Enum(),
					Left:     terms[0],
					Right:    terms[1],
				},
			},
		}
	default:
		panic(fmt.Sprintf(`unexpected operator "%v"`, op))
	}
	return expr
}
