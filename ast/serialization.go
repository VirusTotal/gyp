package ast

import (
	"fmt"

	"github.com/VirusTotal/gyp/pb"
)

// RuleSetFromProto creates a RuleSet from its corresponding protobuf.
func RuleSetFromProto(rs *pb.RuleSet) *RuleSet {
	pbRules := rs.GetRules()
	astRules := make([]*Rule, len(pbRules))
	for i, rule := range pbRules {
		astRules[i] = RuleFromProto(rule)
	}
	return &RuleSet{
		Imports: rs.GetImports(),
		Rules:   astRules,
	}
}

// RuleFromProto creates a Rule from its corresponding protobuf.
func RuleFromProto(r *pb.Rule) *Rule {
	return &Rule{
		Identifier: r.GetIdentifier(),
		Condition:  nodeFromProto(r.GetCondition()),
	}
}

func nodePrecedence(n Node) int {
	switch v := n.(type) {
	case *Operation:
		return OpPrecedence[v.Operator]
	}
	return OpMaxPrecedence
}

// Map for converting operators defined in the protobuf to those used by the AST.
var pbToAst = map[pb.BinaryExpression_Operator]OperatorType{
	pb.BinaryExpression_PLUS:  OpAdd,
	pb.BinaryExpression_MINUS: OpSub,
	pb.BinaryExpression_EQ:    OpEqual,
}

// Map for converting operators defined in the protobuf to those used by the AST.
var astToPb = map[OperatorType]pb.BinaryExpression_Operator{
	OpAdd:   pb.BinaryExpression_PLUS,
	OpSub:   pb.BinaryExpression_MINUS,
	OpEqual: pb.BinaryExpression_EQ,
}

func createOperationNode(operator OperatorType, terms ...*pb.Expression) Node {
	operands := make([]Node, len(terms))
	for i, term := range terms {
		operands[i] = nodeFromProto(term)
		operandPrecedence := nodePrecedence(operands[i])
		// If one of the operands is another operation with lower precedence
		// the operand must be enclosed in parenthesis. If the precedences
		// are the same the parenthesis are not required as long as the
		// operators are left-associative, which is the case for all OperatorType
		if operandPrecedence < OpPrecedence[operator] ||
			operandPrecedence == OpPrecedence[operator] && i > 0 {
			operands[i] = &Group{operands[i]}
		}
	}
	return &Operation{
		Operator: operator,
		Operands: operands,
	}
}

func nodeFromProto(e *pb.Expression) Node {
	switch v := e.GetExpression().(type) {
	case *pb.Expression_AndExpression:
		return createOperationNode(OpAnd, v.AndExpression.GetTerms()...)
	case *pb.Expression_OrExpression:
		return createOperationNode(OpOr, v.OrExpression.GetTerms()...)
	case *pb.Expression_NotExpression:
		operand := nodeFromProto(v.NotExpression)
		// If the operand is an operation with lower precedence than "not",
		// the operand must be enclosed in parenthesis.
		if nodePrecedence(operand) < OpMaxPrecedence {
			operand = &Group{operand}
		}
		return &Not{operand}
	case *pb.Expression_BoolValue:
		if v.BoolValue {
			return KeywordTrue
		}
		return KeywordFalse
	case *pb.Expression_NumberValue:
		return &LiteralInteger{
			Value: v.NumberValue,
		}
	case *pb.Expression_BinaryExpression:
		return createOperationNode(
			pbToAst[v.BinaryExpression.GetOperator()],
			v.BinaryExpression.GetLeft(),
			v.BinaryExpression.GetRight())
	default:
		panic(fmt.Sprintf(`unexpected node "%T"`, v))
	}
}
