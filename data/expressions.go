package data

// A condition is a term which can be:.
// 1. A bool value (either true or false)
// 2. A binary expression, with primary expressions as operands (BinaryExpression).
// 3. A string identifier (string)
// 4. A for expression, in any of its variants. They can contain boolean expressions.
// 5. A primary expression.
// 6. A NOT expression.
// 7. An OR expression.
// 8. An AND expression.

// A primary expression (i.e., expressions not containing boolean expressions) can be:
// 1. A keyword (e.g., filesize) (Keyword).
// 2. A binary primary expression (BinaryPrimaryExpression).
// 3. An integer number (int64).
// 4. A double number (float64).
// 5. A text string (string).
// 6. A string count (StringCount).
// 7. A string offset (StringOffset).
// 8. A string length (StringLength).
// 9. An identifier (Identifier).
// 10. A regular expression (Regex).

// Only one of them
type BooleanExpressionTerm struct {
  BoolValue *bool                           `json:"bool_value,omitempty"`
  *BinaryExpression                         `json:"binary_expression,omitempty"`
  StringIdentifier   string                 `json:"string_identifier,omitempty"`
  *ForInExpression                          `json:"for_in_expression,omitempty"`
  *ForOfExpression                          `json:"for_of_expression,omitempty"`
  *PrimaryExpression                        `json:"primary_expression,omitempty"`
  NotExpression      *BooleanExpressionTerm `json:"not_expression,omitempty"`
  OrExpression                              `json:"or_expression,omitempty"`
  AndExpression                             `json:"and_expression,omitempty"`
}

type OrExpression []BooleanExpressionTerm
type AndExpression []BooleanExpressionTerm

type BinaryOperator string
const (
  MatchesOperator BinaryOperator = "matches"
  ContainsOperator = "contains"
  AtOperator = "at"
  InOperator = "in"
  LtOperator = "<"
  GtOperator = ">"
  LeOperator = "<="
  GeOperator = ">="
  EqOperator = "=="
  NeqOperator = "!="
)

// Models boolean expressions which are non-recursive, i.e., Left and Right cannot
// be boolean expressions. 
type BinaryExpression struct {
  Operator  BinaryOperator            `json:"operator"`
  Left      *BinaryExpressionOperand  `json:"left"`
  Right     *BinaryExpressionOperand  `json:"right,omitempty"`
}

type BinaryExpressionOperand struct {
  *PrimaryExpression          `json:"primary_expression,omitempty"`
  *Regexp                     `json:"regexp,omitempty"`
  StringIdentifier    string  `json:"string_identifier,omitempty"`
  *Range                      `json:"range,omitempty"`
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
  
type PrimaryExpression struct {
  Keyword                   `json:"keyword,omitempty"`
  *BinaryPrimaryExpression  `json:"binary_primary_expression,omitempty"`
  Number          *int64    `json:"number,omitempty"`
  Double          *float64  `json:"double,omitempty"`
  Text            *string   `json:"text,omitempty"`
  *StringCount              `json:"string_count,omitempty"`
  *StringOffset             `json:"string_offset,omitempty"`
  *StringLength             `json:"string_length,omitempty"`
  *Identifier               `json:"identifier,omitempty"`
  *Regexp                   `json:"regexp,omitempty"`
}

type BinaryPrimaryExpression struct {
  Operator PrimaryBinaryOperator            `json:"operator"`
  Left     *BinaryPrimaryExpressionOperand  `json:"left,omitempty"`
  Right    *BinaryPrimaryExpressionOperand  `json:"right,omitempty"`
}

type BinaryPrimaryExpressionOperand struct {
  IntegerFunction *string `json:"integer_function,omitempty"`
  *PrimaryExpression      `json:"primary_expression,omitempty"`
}

type StringCount struct {
  StringIdentifier string `json:"string_identifier"`
}

type StringOffset struct {
  StringIdentifier string             `json:"string_identifier"`
  Index            *PrimaryExpression `json:"index,omitempty"`
}

type StringLength struct {
  StringIdentifier string             `json:"string_identifier"`
  Index            *PrimaryExpression `json:"index,omitempty"`
}

// Either Identifier, Expression or Arguments
type IdentifierItem struct {
  Identifier        string                    `json:"identifier,omitempty"`
  *PrimaryExpression                          `json:"primary_expression,omitempty"`
  Arguments         []BooleanExpressionTerm   `json:"arguments,omitempty"`
}

type Identifier []IdentifierItem

type ForInExpression struct {
  ForExpression                     `json:"for_expression"`
  Identifier  string                `json:"identifier"`
  IntegerSet                        `json:"integer_set"`
  Expression BooleanExpressionTerm  `json:"expression"`
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
  ForExpression                     `json:"for_expression"`
  StringSet                         `json:"string_set"`
  Expression *BooleanExpressionTerm `json:"expression,omitempty"` // Optional
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
