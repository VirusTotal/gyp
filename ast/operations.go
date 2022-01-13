package ast

// OperatorType is the type of operators.
type OperatorType string

// Constants that represents operators.
const (
	OpUnknown        OperatorType = ""
	OpOr             OperatorType = "or"
	OpAnd            OperatorType = "and"
	OpNot            OperatorType = "not"
	OpDefined        OperatorType = "defined"
	OpBitOr          OperatorType = "|"
	OpBitXor         OperatorType = "^"
	OpBitAnd         OperatorType = "&"
	OpEqual          OperatorType = "=="
	OpNotEqual       OperatorType = "!="
	OpLessThan       OperatorType = "<"
	OpGreaterThan    OperatorType = ">"
	OpLessOrEqual    OperatorType = "<="
	OpGreaterOrEqual OperatorType = ">="
	OpAdd            OperatorType = "+"
	OpSub            OperatorType = "-"
	OpMul            OperatorType = "*"
	OpDiv            OperatorType = "\\"
	OpMod            OperatorType = "%"
	OpShiftLeft      OperatorType = "<<"
	OpShiftRight     OperatorType = ">>"
	OpContains       OperatorType = "contains"
	OpIContains      OperatorType = "icontains"
	OpStartsWith     OperatorType = "startswith"
	OpIStartsWith    OperatorType = "istartswith"
	OpEndsWith       OperatorType = "endswith"
	OpIEndsWith      OperatorType = "iendswith"
    OpIEquals        OperatorType = "iequals"
	OpMatches        OperatorType = "matches"
	// Non public operation types. This are operations that exist in the
	// protobuf, but are not translated into an Operation node in the AST.
	// For that reason they are not exported.
	opAt OperatorType = "at"
	opIn OperatorType = "in"
)

// OpPrecedence is the operator precedence table.
var OpPrecedence = map[OperatorType]int{
	OpOr:             0,
	OpAnd:            1,
	OpNot:            2,
	OpEqual:          3,
	OpNotEqual:       3,
	OpLessThan:       4,
	OpLessOrEqual:    4,
	OpGreaterThan:    4,
	OpGreaterOrEqual: 4,
	OpContains:       4,
	OpIContains:      4,
	OpStartsWith:     4,
	OpIStartsWith:    4,
	OpEndsWith:       4,
	OpIEndsWith:      4,
	OpIEquals:        4,
	OpMatches:        4,
	OpBitOr:          5,
	OpBitXor:         6,
	OpBitAnd:         7,
	OpShiftLeft:      8,
	OpShiftRight:     8,
	OpAdd:            9,
	OpSub:            9,
	OpMul:            10,
	OpDiv:            10,
	OpMod:            10,
}

// OpMaxPrecedence is the maximum possible precedence. This is also the precedence
// for unary operators "~" and "-".
const OpMaxPrecedence = 11
