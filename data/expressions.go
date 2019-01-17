package data

import (
  "fmt"
)

// A condition is a term which can be:.
// 1. A bool value (either true or false)
// 2. A binary expression, with primary expressions as operands (BinaryExpression).
// 3. A string identifier (string)
// 4. A for expression, in any of its variants. They can contain boolean expressions.
// 5. A primary expression.
// 6. A NOT expression.
// 7. An OR expression.

// A primary expression (i.e., expressions not containing boolean expressions) can be:
// 1. A keyword (e.g., filesize) (Keyword).
// 2. A binary primary expression (BinaryPrimaryExpression).
// 3. An integer number (int).
// 4. A double number (float64).
// 5. A text string (string).
// 6. A string count (StringCount).
// 7. A string offset (StringOffset).
// 8. A string length (StringLength).
// 9. An identifier (Identifier).
// 10. A regular expression (Regex).

func (e OrExpression) String() string {
  return "boolean expression"
}

type PrimaryExpression interface{}

type OrExpression []BooleanExpressionTerm

type AndExpression []BooleanExpressionTerm

// Only one of them
type BooleanExpressionTerm struct {
  BoolValue *bool                           `json:"bool_value,omitempty"`
  *BinaryExpression                         `json:"binary_expression,omitempty"`
  StringIdentifier  string                  `json:"string_identifier,omitempty"`
  *ForInExpression                          `json:"for_in_expression,omitempty"`
  *ForOfExpression                          `json:"for_of_expression,omitempty"`
  PrimaryExpression                         `json:"primary_expression,omitempty"`
  NotExpression     *BooleanExpressionTerm  `json:"not_expression,omitempty"`
  *OrExpression                             `json:"or_expression,omitempty"` 
  *AndExpression                            `json:"and_expression,omitempty"`
}

func (e BooleanExpressionTerm) String() string {
  return fmt.Sprintf("%s", e)
}

type BinaryOperator string
const (
  MatchesOperator BinaryOperator = "matches"
  ContainsOperator = "contains"
  AtOperator = "at"
  InOperator = "in"
  LtOperator = "lt"
  GtOperator = "gt"
  LeOperator = "le"
  GeOperator = "ge"
  EqOperator = "eq"
  NeqOperator = "neq"
)

// Models boolean expressions which are non-recursive, i.e., Left and Right cannot
// be boolean expressions. 
type BinaryExpression struct {
  Operator BinaryOperator `json:"operator"`
  Left interface{}        `json:"left"`
  Right interface{}       `json:"right"`
}

type NotExpression BooleanExpressionTerm
  
type Keyword string

const (
  EntrypointKeyword Keyword = "entrypoint"
  FilesizeKeyword = "filesize"
  ThemKeyword = "them"
  AllKeyword = "all"
  AnyKeyword = "any"
)
  
type PrimaryBinaryOperator string
const (
  IntegerFunctionOperator PrimaryBinaryOperator = "integer_function"
  UnaryMinusOperator = "unary_minus"
  PlusOperator = "+"
  MinusOperator = "-"
  TimesOperator = "*"
  DivOperator = "\\"
  ModOperator = "%"
  XorOperator = "^"
  BitwiseAndOperator = "&"
  BitwiseOrOperator = "|"
  BitwiseNotOperator = "~"
  ShiftLeftOperator = "<<"
  ShiftRightOperator = ">>"
)
  
type BinaryPrimaryExpression struct {
  Operator PrimaryBinaryOperator  `json:"operator"`
  Left interface{}                `json:"left"`
  Right interface{}               `json:"right,omitempty"`
}

type StringCount struct {
  StringIdentifier string         `json:"string_identifier"`
}

type StringOffset struct {
  StringIdentifier string             `json:"string_identifier"`
  Index            PrimaryExpression  `json:"index"`
}

type StringLength struct {
  StringIdentifier string             `json:"string_identifier"`
  Index            PrimaryExpression  `json:"index"`
}

// Either Identifier, Expression or Arguments
type IdentifierItem struct {
  Identifier        string                    `json:"identifier,omitempty"`
  PrimaryExpression                           `json:"primary_expression,omitempty"`
  Arguments         []BooleanExpressionTerm   `json:"arguments,omitempty"`
}

type Identifier []IdentifierItem

type ForInExpression struct {
  ForExpression           `json:"for_expression"`
  Identifier  string      `json:"identifier"`
  IntegerSet              `json:"integer_set"`
  Expression  interface{} `json:"expression"` // BooleanExpressionTerm
}

// Either IntegerEnumeration or Range
type IntegerSet struct {
  IntegerEnumeration  []PrimaryExpression `json:"integer_enumeration,omitempty"`
  *Range                                  `json:"range,omitempty"`
}

type Range struct {
  Start PrimaryExpression `json:"start"`
  End   PrimaryExpression `json:"end"`
}

// Either PrimaryExpression, All or Any
type ForExpression struct {
  PrimaryExpression `json:"primary_expression,omitempty"`
  Keyword           `json:"keyword,omitempty"` // Either "all" or "any"
}

type ForOfExpression struct {
  ForExpression           `json:"for_expression"`
  StringSet               `json:"string_set"`
  Expression interface{}  `json:"expression,omitempty"` // Optional
}

// Either StringEnumeration or Keyword
type StringSet struct {
  StringEnumeration []StringEnumerationItem `json:"string_enumeration,omitempty"`
  Keyword                                   `json:"keyword,omitempty"` // Allowed value: "them"
}

type StringEnumerationItem struct {
  StringIdentifier string `json:"string_identifier"`
  HasWildcard bool        `json:"has_wildcard"`
}
