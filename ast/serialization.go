package ast

import (
	"fmt"
	"strings"

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
		Imports:  rs.GetImports(),
		Includes: rs.GetIncludes(),
		Rules:    astRules,
	}
}

// RuleFromProto creates a Rule from its corresponding protobuf.
func RuleFromProto(r *pb.Rule) *Rule {
	pbStrings := r.GetStrings()
	astStrings := make([]String, len(pbStrings))
	for i, s := range pbStrings {
		astStrings[i] = stringFromProto(s)
	}
	pbMeta := r.GetMeta()
	astMeta := make([]*Meta, len(pbMeta))
	for i, m := range pbMeta {
		astMeta[i] = metaFromProto(m)
	}
	return &Rule{
		Global:     r.GetModifiers().GetGlobal(),
		Private:    r.GetModifiers().GetPrivate(),
		Tags:       r.GetTags(),
		Identifier: r.GetIdentifier(),
		Strings:    astStrings,
		Meta:       astMeta,
		Condition:  expressionFromProto(r.GetCondition()),
	}
}

// If the expression is an operation returns the operator's precedence level,
// if not, returns the maximum possible precedence level.
func expressionPrecedence(e Expression) int {
	switch v := e.(type) {
	case *Operation:
		return OpPrecedence[v.Operator]
	}
	return OpMaxPrecedence
}

// Map for converting operators defined in the protobuf to those used by the AST.
var pbToAst = map[pb.BinaryExpression_Operator]OperatorType{
	pb.BinaryExpression_BITWISE_OR:  OpBitOr,
	pb.BinaryExpression_BITWISE_AND: OpBitAnd,
	pb.BinaryExpression_XOR:         OpBitXor,
	pb.BinaryExpression_EQ:          OpEqual,
	pb.BinaryExpression_NEQ:         OpNotEqual,
	pb.BinaryExpression_LT:          OpLessThan,
	pb.BinaryExpression_GT:          OpGreaterThan,
	pb.BinaryExpression_LE:          OpLessOrEqual,
	pb.BinaryExpression_GE:          OpGreaterOrEqual,
	pb.BinaryExpression_PLUS:        OpAdd,
	pb.BinaryExpression_MINUS:       OpSub,
	pb.BinaryExpression_TIMES:       OpMul,
	pb.BinaryExpression_DIV:         OpDiv,
	pb.BinaryExpression_MOD:         OpMod,
	pb.BinaryExpression_SHIFT_LEFT:  OpShiftLeft,
	pb.BinaryExpression_SHIFT_RIGHT: OpShiftRight,
	pb.BinaryExpression_CONTAINS:    OpContains,
	pb.BinaryExpression_ICONTAINS:   OpIContains,
	pb.BinaryExpression_STARTSWITH:  OpStartsWith,
	pb.BinaryExpression_ISTARTSWITH: OpIStartsWith,
	pb.BinaryExpression_ENDSWITH:    OpEndsWith,
	pb.BinaryExpression_IENDSWITH:   OpIEndsWith,
	pb.BinaryExpression_MATCHES:     OpMatches,
	// Operations that exist in the protobuf but are not translated to an
	// operation in the AST.
	pb.BinaryExpression_AT: opAt,
	pb.BinaryExpression_IN: opIn,
}

// Map for converting operators defined in the protobuf to those used by the AST.
var astToPb = map[OperatorType]pb.BinaryExpression_Operator{
	OpBitOr:          pb.BinaryExpression_BITWISE_OR,
	OpBitAnd:         pb.BinaryExpression_BITWISE_AND,
	OpBitXor:         pb.BinaryExpression_XOR,
	OpEqual:          pb.BinaryExpression_EQ,
	OpNotEqual:       pb.BinaryExpression_NEQ,
	OpLessThan:       pb.BinaryExpression_LT,
	OpGreaterThan:    pb.BinaryExpression_GT,
	OpLessOrEqual:    pb.BinaryExpression_LE,
	OpGreaterOrEqual: pb.BinaryExpression_GE,
	OpAdd:            pb.BinaryExpression_PLUS,
	OpSub:            pb.BinaryExpression_MINUS,
	OpMul:            pb.BinaryExpression_TIMES,
	OpDiv:            pb.BinaryExpression_DIV,
	OpMod:            pb.BinaryExpression_MOD,
	OpShiftLeft:      pb.BinaryExpression_SHIFT_LEFT,
	OpShiftRight:     pb.BinaryExpression_SHIFT_RIGHT,
	OpContains:       pb.BinaryExpression_CONTAINS,
	OpIContains:      pb.BinaryExpression_ICONTAINS,
	OpStartsWith:     pb.BinaryExpression_STARTSWITH,
	OpIStartsWith:    pb.BinaryExpression_ISTARTSWITH,
	OpEndsWith:       pb.BinaryExpression_ENDSWITH,
	OpIEndsWith:      pb.BinaryExpression_IENDSWITH,
	OpMatches:        pb.BinaryExpression_MATCHES,
}

// createOperationExpression creates an operation given an operator and a list of
// terms (as *pb.Expression) that will become the operands. Operands are enclosed
// in parenthesis if they are another operation with lower precedence. If the
// precedence level is the same the operand is also enclosed in parenthesis,
// except for the left-most operand, which won't require parenthesis if the operator
// is left-associative. So, this function can be used with left-associative operators.
func createOperationExpression(operator OperatorType, terms ...*pb.Expression) Expression {
	operands := expressionsFromProto(terms...)
	for i, operand := range operands {
		operandPrecedence := expressionPrecedence(operand)
		if operandPrecedence < OpPrecedence[operator] ||
			operandPrecedence == OpPrecedence[operator] && i > 0 {
			operands[i] = &Group{operand}
		}
	}
	return &Operation{
		Operator: operator,
		Operands: operands,
	}
}

func createIdentifierExpression(ident *pb.Identifier) Expression {
	var expr Expression
	for _, item := range ident.GetItems() {
		switch v := item.GetItem().(type) {
		case *pb.Identifier_IdentifierItem_Identifier:
			if expr != nil {
				expr = &MemberAccess{Container: expr, Member: v.Identifier}
			} else {
				expr = &Identifier{Identifier: v.Identifier}
			}
		case *pb.Identifier_IdentifierItem_Arguments:
			if expr == nil {
				panic("arguments can't be the left-most item in an identifer")
			}
			expr = &FunctionCall{
				Callable:  expr,
				Arguments: expressionsFromProto(v.Arguments.GetTerms()...)}
		case *pb.Identifier_IdentifierItem_Index:
			if expr == nil {
				panic("index can't be the left-most item in an identifer")
			}
			expr = &Subscripting{
				Array: expr,
				Index: expressionFromProto(v.Index),
			}
		}
	}
	return expr
}

func stringFromProto(s *pb.String) String {
	switch v := s.GetValue().(type) {
	case *pb.String_Text:
		modifiers := v.Text.GetModifiers()
		return &TextString{
			BaseString: BaseString{
				Identifier: strings.TrimPrefix(s.GetId(), "$"),
			},
			ASCII:          modifiers.GetAscii(),
			Wide:           modifiers.GetWide(),
			Nocase:         modifiers.GetNocase(),
			Fullword:       modifiers.GetFullword(),
			Private:        modifiers.GetPrivate(),
			Xor:            modifiers.GetXor(),
			XorMin:         modifiers.GetXorMin(),
			XorMax:         modifiers.GetXorMax(),
			Base64:         modifiers.GetBase64(),
			Base64Wide:     modifiers.GetBase64Wide(),
			Base64Alphabet: modifiers.GetBase64Alphabet(),
			Value:          Escape(v.Text.GetText()),
		}
	case *pb.String_Hex:
		return &HexString{
			BaseString: BaseString{
				Identifier: strings.TrimPrefix(s.GetId(), "$"),
			},
			Tokens: hexTokensFromProto(v.Hex),
		}
	case *pb.String_Regexp:
		modifiers := v.Regexp.GetModifiers()
		var regexpm RegexpModifiers
		if modifiers.GetI() {
			regexpm |= RegexpCaseInsensitive
		}
		if modifiers.GetS() {
			regexpm |= RegexpDotAll
		}
		return &RegexpString{
			BaseString: BaseString{
				Identifier: strings.TrimPrefix(s.GetId(), "$"),
			},
			ASCII:    modifiers.GetAscii(),
			Wide:     modifiers.GetWide(),
			Nocase:   modifiers.GetNocase(),
			Fullword: modifiers.GetFullword(),
			Private:  modifiers.GetPrivate(),
			Regexp: &LiteralRegexp{
				Value:     v.Regexp.GetText(),
				Modifiers: regexpm,
			},
		}
	default:
		panic(fmt.Sprintf(`unexpected string "%T"`, v))
	}
}

func hexTokensFromProto(pbTokens *pb.HexTokens) HexTokens {
	tokens := make(HexTokens, len(pbTokens.GetToken()))
	for i, token := range pbTokens.GetToken() {
		switch v := token.GetValue().(type) {
		case *pb.HexToken_Sequence:
			tokens[i] = &HexBytes{
				Bytes: v.Sequence.GetValue(),
				Masks: v.Sequence.GetMask(),
			}
		case *pb.HexToken_Alternative:
			alternatives := make(HexTokens, len(v.Alternative.GetTokens()))
			for i, a := range v.Alternative.GetTokens() {
				alternatives[i] = hexTokensFromProto(a)
			}
			tokens[i] = &HexOr{
				Alternatives: alternatives,
			}
		case *pb.HexToken_Jump:
			tokens[i] = &HexJump{
				Start: int(v.Jump.GetStart()),
				End:   int(v.Jump.GetEnd()),
			}
		}
	}
	return tokens
}

func metaFromProto(m *pb.Meta) *Meta {
	var value interface{}
	switch v := m.GetValue().(type) {
	case *pb.Meta_Boolean:
		value = v.Boolean
	case *pb.Meta_Number:
		value = v.Number
	case *pb.Meta_Text:
		value = v.Text
	}
	return &Meta{
		Key:   m.GetKey(),
		Value: value,
	}
}

func rangeFromProto(r *pb.Range) *Range {
	if r == nil {
		return nil
	}
	return &Range{
		Start: expressionFromProto(r.GetStart()),
		End:   expressionFromProto(r.GetEnd()),
	}
}

func enumFromProto(e *pb.IntegerEnumeration) *Enum {
	if e == nil {
		return nil
	}
	values := make([]Expression, len(e.GetValues()))
	for i, v := range e.GetValues() {
		values[i] = expressionFromProto(v)
	}
	return &Enum{
		Values: values,
	}
}

func quantifierFromProto(expr *pb.ForExpression) *Quantifier {
	if expr == nil {
		return nil
	}
	var q Expression
	switch v := expr.GetFor().(type) {
	case *pb.ForExpression_Keyword:
		if v.Keyword == pb.ForKeyword_ALL {
			q = KeywordAll
		} else if v.Keyword == pb.ForKeyword_ANY {
			q = KeywordAny
		} else if v.Keyword == pb.ForKeyword_NONE {
			q = KeywordNone
		}
	case *pb.ForExpression_Expression:
		q = expressionFromProto(v.Expression)
	}
	return &Quantifier{q}
}

func forInExpressionFromProto(expr *pb.ForInExpression) *ForIn {
	var iterator Node
	switch v := expr.GetIterator().GetIterator().(type) {
	case *pb.Iterator_Identifier:
		iterator = createIdentifierExpression(v.Identifier)
	case *pb.Iterator_IntegerSet:
		iterator = rangeFromProto(v.IntegerSet.GetRange())
		// If not a range it must be an enumeration.
		if iterator.(*Range) == nil {
			iterator = enumFromProto(v.IntegerSet.GetIntegerEnumeration())
		}
	}
	return &ForIn{
		Quantifier: quantifierFromProto(expr.GetForExpression()),
		Variables:  expr.GetIdentifiers(),
		Iterator:   iterator,
		Condition:  expressionFromProto(expr.GetExpression()),
	}
}

func forOfExpressionFromProto(expr *pb.ForOfExpression) Expression {
	var strs Node
	switch v := expr.GetStringSet().GetSet().(type) {
	case *pb.StringSet_Strings:
		items := v.Strings.GetItems()
		enum := &Enum{
			Values: make([]Expression, len(items)),
		}
		for i, item := range items {
			enum.Values[i] = &StringIdentifier{
				Identifier: strings.TrimPrefix(item.GetStringIdentifier(), "$"),
			}
		}
		strs = enum
	case *pb.StringSet_Keyword:
		if v.Keyword != pb.StringSetKeyword_THEM {
			panic(fmt.Sprintf(`unexpected keyword "%T"`, v))
		}
		strs = KeywordThem
	}
	condition := expr.GetExpression()
	// A "<quantifier> of <string_set>" expression is serialized to protobuf
	// as a "for <quantifier> of <string_set> : (<condition>)", where <condition>
	// is nil. So, if condition is nil we return a Of expression instead of a
	// ForOf expression
	if condition == nil {
		return &Of{
			Quantifier: quantifierFromProto(expr.GetForExpression()),
			Strings:    strs,
		}
	}
	return &ForOf{
		Quantifier: quantifierFromProto(expr.GetForExpression()),
		Strings:    strs,
		Condition:  expressionFromProto(expr.GetExpression()),
	}
}

func binaryExpressionFromProto(expr *pb.BinaryExpression) Expression {
	switch op := pbToAst[expr.GetOperator()]; op {
	// The "at" and "in" operations are represented as a binary operation
	// in the protobuf, but in the AST is represented as a field in a
	// StringIdentifier expression.
	case opAt:
		return &StringIdentifier{
			Identifier: strings.TrimPrefix(expr.GetLeft().GetStringIdentifier(), "$"),
			At:         expressionFromProto(expr.GetRight()),
		}
	case opIn:
		switch v := expr.GetLeft().GetExpression().(type) {
		case *pb.Expression_StringIdentifier:
			return &StringIdentifier{
				Identifier: strings.TrimPrefix(expr.GetLeft().GetStringIdentifier(), "$"),
				In:         rangeFromProto(expr.GetRight().GetRange()),
			}
		case *pb.Expression_StringCount:
			return &StringCount{
				Identifier: strings.TrimPrefix(expr.GetLeft().GetStringCount(), "#"),
				In:         rangeFromProto(expr.GetRight().GetRange()),
			}
		default:
			panic(fmt.Sprintf(`unexpected binary expression "%v"`, v))
		}
	default:
		return createOperationExpression(op, expr.GetLeft(), expr.GetRight())
	}
}

func expressionsFromProto(pbExpressions ...*pb.Expression) []Expression {
	expressions := make([]Expression, len(pbExpressions))
	for i, e := range pbExpressions {
		expressions[i] = expressionFromProto(e)
	}
	return expressions
}

func expressionFromProto(e *pb.Expression) Expression {
	if e == nil {
		return nil
	}
	switch v := e.GetExpression().(type) {
	case *pb.Expression_BoolValue:
		if v.BoolValue {
			return KeywordTrue
		}
		return KeywordFalse
	case *pb.Expression_NumberValue:
		return &LiteralInteger{
			Value: v.NumberValue,
		}
	case *pb.Expression_DoubleValue:
		return &LiteralFloat{
			Value: v.DoubleValue,
		}
	case *pb.Expression_Text:
		return &LiteralString{
			Value: v.Text,
		}
	case *pb.Expression_Regexp:
		var mods RegexpModifiers
		pbmods := v.Regexp.GetModifiers()
		if pbmods.GetI() {
			mods |= RegexpCaseInsensitive
		}
		if pbmods.GetS() {
			mods |= RegexpDotAll
		}
		return &LiteralRegexp{
			Value:     v.Regexp.GetText(),
			Modifiers: mods,
		}
	case *pb.Expression_StringIdentifier:
		return &StringIdentifier{
			Identifier: strings.TrimPrefix(v.StringIdentifier, "$"),
		}
	case *pb.Expression_StringCount:
		return &StringCount{
			Identifier: strings.TrimPrefix(v.StringCount, "#"),
		}
	case *pb.Expression_StringLength:
		return &StringLength{
			Identifier: strings.TrimPrefix(v.StringLength.GetStringIdentifier(), "!"),
			Index:      expressionFromProto(v.StringLength.GetIndex()),
		}
	case *pb.Expression_StringOffset:
		return &StringOffset{
			Identifier: strings.TrimPrefix(v.StringOffset.GetStringIdentifier(), "@"),
			Index:      expressionFromProto(v.StringOffset.GetIndex()),
		}
	case *pb.Expression_Identifier:
		return createIdentifierExpression(v.Identifier)
	case *pb.Expression_AndExpression:
		return createOperationExpression(OpAnd, v.AndExpression.GetTerms()...)
	case *pb.Expression_OrExpression:
		return createOperationExpression(OpOr, v.OrExpression.GetTerms()...)
	case *pb.Expression_NotExpression:
		operand := expressionFromProto(v.NotExpression)
		// If the operand is an operation with lower precedence than "not",
		// the operand must be enclosed in parenthesis.
		if expressionPrecedence(operand) < OpMaxPrecedence {
			operand = &Group{operand}
		}
		return &Not{operand}
	case *pb.Expression_UnaryExpression:
		operand := expressionFromProto(v.UnaryExpression.GetExpression())
		// If the operand is an operation with lower precedence than "-" or "~",
		// the operand must be enclosed in parenthesis.
		if expressionPrecedence(operand) < OpMaxPrecedence {
			operand = &Group{operand}
		}
		switch op := v.UnaryExpression.Operator; *op {
		case pb.UnaryExpression_UNARY_MINUS:
			return &Minus{operand}
		case pb.UnaryExpression_BITWISE_NOT:
			return &BitwiseNot{operand}
		default:
			panic(fmt.Sprintf(`unexpected unary operator "%v"`, op))
		}
	case *pb.Expression_BinaryExpression:
		return binaryExpressionFromProto(v.BinaryExpression)
	case *pb.Expression_ForInExpression:
		return forInExpressionFromProto(v.ForInExpression)
	case *pb.Expression_ForOfExpression:
		return forOfExpressionFromProto(v.ForOfExpression)
	case *pb.Expression_Keyword:
		switch keyword := v.Keyword; keyword {
		case pb.Keyword_ENTRYPOINT:
			return KeywordEntrypoint
		case pb.Keyword_FILESIZE:
			return KeywordFilesize
		default:
			panic(fmt.Sprintf(`unknown keyword "%T"`, keyword))
		}
	case *pb.Expression_PercentageExpression:
		return &Percentage{
			Expression: expressionFromProto(v.PercentageExpression.Expression),
		}
	default:
		panic(fmt.Sprintf(`unexpected node "%T"`, v))
	}
}
