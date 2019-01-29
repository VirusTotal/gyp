// Functions and methods for serializing a RuleSet proto to YARA rules as strings.

package data

import (
  "math"
	"fmt"
	"strings"
)

var keywords = map[Keyword]string {
  Keyword_ENTRYPOINT: "entrypoint",
  Keyword_FILESIZE: "filesize",
  Keyword_THEM: "them",
  Keyword_ALL: "all",
  Keyword_ANY: "any",
}

var operators = map[BinaryExpression_Operator]string {
  BinaryExpression_MATCHES: "matches",
  BinaryExpression_CONTAINS: "contains",
  BinaryExpression_AT: "at",
  BinaryExpression_IN: "in",
  BinaryExpression_BITWISE_OR: "|",
  BinaryExpression_XOR: "^",
  BinaryExpression_BITWISE_AND: "&",
  BinaryExpression_EQ: "==",
  BinaryExpression_NEQ: "!=",
  BinaryExpression_LT: "<",
  BinaryExpression_LE: "<=",
  BinaryExpression_GT: ">",
  BinaryExpression_GE: ">=",
  BinaryExpression_SHIFT_LEFT: "<<",
  BinaryExpression_SHIFT_RIGHT: ">>",
  BinaryExpression_PLUS: "+",
  BinaryExpression_MINUS: "-",
  BinaryExpression_TIMES: "*",
  BinaryExpression_DIV: "\\",
  BinaryExpression_MOD: "%",
}

const precedenceOrExpression int8 = 1
const precedenceAndExpression int8 = 2

// Operators AT, IN, MATCHES and CONTAINS do not have a specified precedence.
// In those cases, the maximum precedence value should be assumed to prevent
// adding unnecessary parenthesis.
var binaryOperatorsPrecedence = map[BinaryExpression_Operator]int8 {
  BinaryExpression_BITWISE_OR: 3,
  BinaryExpression_XOR: 4,
  BinaryExpression_BITWISE_AND: 5,
  BinaryExpression_EQ: 6,
  BinaryExpression_NEQ: 6,
  BinaryExpression_LT: 7,
  BinaryExpression_LE: 7,
  BinaryExpression_GT: 7,
  BinaryExpression_GE: 7,
  BinaryExpression_SHIFT_LEFT: 8,
  BinaryExpression_SHIFT_RIGHT: 8,
  BinaryExpression_PLUS: 9,
  BinaryExpression_MINUS: 9,
  BinaryExpression_TIMES: 10,
  BinaryExpression_DIV: 10,
  BinaryExpression_MOD: 10,
}
const precedenceNotExpression int8 = 15
const precedenceUnaryExpression int8 = 15

func (e *Expression) getPrecedence() int8 {
  switch e.GetExpression().(type) {
  case *Expression_OrExpression:
    return precedenceOrExpression
  case *Expression_AndExpression:
    return precedenceAndExpression
  case *Expression_BinaryExpression:
    return e.GetBinaryExpression().getPrecedence()
  case *Expression_NotExpression:
    return precedenceNotExpression
  case *Expression_UnaryExpression:
    return precedenceUnaryExpression
  }

  // Expression with no precedence defined. Return maximum value.
  return math.MaxInt8
}

// Serializes a complete YARA ruleset.
func (rs *RuleSet) Serialize() (out string, err error) {
	var b strings.Builder

	if len(rs.Includes) > 0 {
		for _, include := range rs.Includes {
			b.WriteString(fmt.Sprintf("include \"%s\"\n", include))
		}
		b.WriteRune('\n')
	}

	if len(rs.Imports) > 0 {
		for _, imp := range rs.Imports {
			b.WriteString(fmt.Sprintf("import \"%s\"\n", imp))
		}
		b.WriteRune('\n')
	}

	for _, rule := range rs.Rules {
		str, err := rule.Serialize()
		if err != nil {
			return "", err
		}
		b.WriteString(str)
	}

	out = b.String()
	return
}

// Serializes a YARA rule.
func (r *Rule) Serialize() (out string, err error) {
	var b strings.Builder

	// Rule modifiers
	if r.Modifiers.GetGlobal() {
		b.WriteString("global ")
	}
	if r.Modifiers.GetPrivate() {
		b.WriteString("private ")
	}

	// Rule name
	b.WriteString(fmt.Sprintf("rule %s ", r.GetIdentifier()))

	// Any applicable tags
	if len(r.Tags) > 0 {
		b.WriteString(": ")
		for _, t := range r.Tags {
			b.WriteString(t)
			b.WriteRune(' ')
		}
	}

	// Start metas, strings, etc.
	b.WriteString("{\n")

  metas, err := SerializeMetas(r.Meta)
	if err != nil {
		return
	}
	b.WriteString(metas)

  strs, err := SerializeStrings(r.Strings)
  if err != nil {
   return
  }
  b.WriteString(strs)

	b.WriteString("condition:\n")
	b.WriteString("  ") // TODO: Don't assume indent...
  str, err := r.Condition.Serialize()
  if err != nil {
     return
   }
	b.WriteString(str)
	b.WriteString("\n}\n\n")

	out = b.String()
	return
}

// Serializes the "meta:" section in a YARA rule.
func SerializeMetas(ms []*Meta) (out string, err error) {
 	if ms == nil || len(ms) == 0 {
 		return
 	}
 
 	var b strings.Builder
 	b.WriteString("meta:\n")
 
 	for _, m := range ms {
 		meta, e := m.Serialize()
 		if e != nil {
 			err = e
 			return
 		}
 		b.WriteString("  ") // TODO: make indent customizable
 		b.WriteString(meta)
 		b.WriteRune('\n')
 	}
 
 	out = b.String()
 	return
}

// Serializes a Meta declaration (key/value pair) in a YARA rule.
func (m *Meta) Serialize() (out string, err error) {
 	switch val := m.GetValue().(type) {
 	case *Meta_Text:
 		out = fmt.Sprintf(`%s = "%s"`, m.GetKey(), m.GetText())
  case *Meta_Number:
 		out = fmt.Sprintf(`%s = %v`, m.GetKey(), m.GetNumber())
  case *Meta_Boolean:
 		out = fmt.Sprintf(`%s = %v`, m.GetKey(), m.GetBoolean())
 	default:
 		err = fmt.Errorf(`Unsupported meta value type "%s"`, val)
    return
 	}
 
 	return
}

// Serializes the "strings:" section in a YARA rule.
func SerializeStrings(strs []*String) (out string, err error) {
  if strs == nil || len(strs) == 0 {
    return
  }

  var b strings.Builder
  b.WriteString("strings:\n")

  for _, s := range strs {
    str, e := s.Serialize()
    if e != nil {
      err = e
      return
    }

    b.WriteString("  ")
    b.WriteString(str)
    b.WriteRune('\n')
  }

  out = b.String()
  return
}

// Serializes a RegExp, appending the i and s modifiers if included.
// The returned error must be nil.
func (r *Regexp) Serialize() (out string, _ error) {
  var b strings.Builder
  b.WriteRune('/')
  b.WriteString(r.GetText())
  b.WriteRune('/')

  if (r.Modifiers.GetI()) {
    b.WriteRune('i')
  }
  if (r.Modifiers.GetS()) {
    b.WriteRune('s')
  }

  out = b.String()
  return
}

// Serialize for String returns a String as a string
func (s *String) Serialize() (out string, err error) {
  // Format string for:
  // `<identifier> = <encapsOpen> <text> <encapsClose> <modifiers>`
  format := "%s = %s%s%s %s"

  var (
    encapsOpen  string
    encapsClose string
  )
  switch t := s.GetType(); t {
  case String_TEXT:
    encapsOpen, encapsClose = `"`, `"`
  case String_HEX:
    encapsOpen, encapsClose = "{", "}"
  case String_REGEX:
    encapsOpen = "/"
	  var closeBuilder strings.Builder
      closeBuilder.WriteRune('/')
	  if s.Modifiers.GetI() {
		  closeBuilder.WriteRune('i')
	  }
	  if s.Modifiers.GetS() {
		  closeBuilder.WriteRune('s')
	  }
	  encapsClose = closeBuilder.String()
  default:
	  err = fmt.Errorf("No such string type %s (%d)", t, t)
    return
  }

  mods, _ := s.Modifiers.Serialize()
  out = fmt.Sprintf(format, s.GetId(), encapsOpen, s.GetText(), encapsClose, mods)
  return
}

// Serialize for StringModifiers creates a space-sparated list of
// string modifiers, excluding the i and s which are appended to /regex/
// The returned error must be nil.
func (m *StringModifiers) Serialize() (out string, _ error) {
  const modsAvailable = 4
	modifiers := make([]string, 0, modsAvailable)
	if m.GetAscii() {
		modifiers = append(modifiers, "ascii")
	}
	if m.GetWide() {
		modifiers = append(modifiers, "wide")
	}
	if m.GetNocase() {
		modifiers = append(modifiers, "nocase")
	}
	if m.GetFullword() {
		modifiers = append(modifiers, "fullword")
	}
	if m.GetXor() {
		modifiers = append(modifiers, "xor")
	}

	out = strings.Join(modifiers, " ")
	return
}

// Serializes an Expression in a YARA rule condition.
func (e *Expression) Serialize() (out string, err error) {
  switch val := e.GetExpression().(type) {
  case *Expression_OrExpression:
    out, err = e.GetExpression().(*Expression_OrExpression).Serialize()
  case *Expression_AndExpression:
    out, err = e.GetExpression().(*Expression_AndExpression).Serialize()
  case *Expression_StringIdentifier:
    out = e.GetStringIdentifier()
  case *Expression_ForInExpression:
    out, err = e.GetForInExpression().Serialize()
  case *Expression_ForOfExpression:
    out, err = e.GetForOfExpression().Serialize()
  case *Expression_BinaryExpression:
    out, err = e.GetBinaryExpression().Serialize()
  case *Expression_Text:
    var b strings.Builder
    b.WriteRune('"')
    b.WriteString(e.GetText())
    b.WriteRune('"')
    out = b.String()
  case *Expression_NumberValue:
    out = fmt.Sprintf("%d", e.GetNumberValue())
  case *Expression_DoubleValue:
    out = fmt.Sprintf("%f", e.GetDoubleValue())
  case *Expression_Range:
    out, err = e.GetRange().Serialize()
  case *Expression_Keyword:
    out, err = e.GetKeyword().Serialize()
  case *Expression_Identifier:
    out, err = e.GetIdentifier().Serialize()
  case *Expression_Regexp:
    out, err = e.GetRegexp().Serialize()
  case *Expression_NotExpression:
    not := e.GetExpression().(*Expression_NotExpression)
    out, err = not.Serialize()
  case *Expression_IntegerFunction:
    out, err = e.GetIntegerFunction().Serialize()
  case *Expression_StringOffset:
    out, err = e.GetStringOffset().Serialize()
  case *Expression_StringLength:
    out, err = e.GetStringLength().Serialize()
  case *Expression_StringCount:
    out = e.GetStringCount()
  default:
    err = fmt.Errorf(`Unsupported expression type "%T"`, val)
    return
  }

  return
}

// Serializes a StringOffset.
func (e *StringOffset) Serialize() (out string, err error) {
  var b strings.Builder
  b.WriteString(e.GetStringIdentifier())
  if (e.GetIndex() != nil) {
    b.WriteRune('[')
    var str string
    str, err = e.GetIndex().Serialize()
    if err != nil {
      return
    }
    b.WriteString(str)
    b.WriteRune(']')
  }

  out = b.String()
  return
}

// Serializes a StringLength.
func (e *StringLength) Serialize() (out string, err error) {
  var b strings.Builder
  b.WriteString(e.GetStringIdentifier())
  if (e.GetIndex() != nil) {
    b.WriteRune('[')
    var str string
    str, err = e.GetIndex().Serialize()
    if err != nil {
      return
    }
    b.WriteString(str)
    b.WriteRune(']')
  }

  out = b.String()
  return
}

// Serializes an IntegerFunction.
func (e *IntegerFunction) Serialize() (out string, err error) {
  var b strings.Builder
  b.WriteString(e.GetFunction())
  b.WriteRune('(')
  str, err := e.GetExpression().Serialize()
  if err != nil {
    return
  }
  b.WriteString(str)
  b.WriteRune(')')

  out = b.String()
  return
}

// Serializes a NOT expression.
func (e *Expression_NotExpression) Serialize() (out string, err error) {
  var b strings.Builder
  b.WriteString("not ")
  str, err := e.NotExpression.Serialize()
  if err != nil {
    return
  }

  if (e.NotExpression.getPrecedence() < precedenceNotExpression) {
    b.WriteRune('(')
    b.WriteString(str)
    b.WriteRune(')')
  } else {
    b.WriteString(str)
  }
  out = b.String()
  return
}

// Serializes an OR expression.
func (e *Expression_OrExpression) Serialize() (out string, err error) {
  strs, err := mapTermsToStrings(e.OrExpression.Terms)
  if err != nil {
    return
  }

  out = strings.Join(strs, " or ")
  return
}

// Serializes an AND expression.
func (e *Expression_AndExpression) Serialize() (out string, err error) {
  strs, err := mapTermsToStrings(e.AndExpression.Terms)
  if err != nil {
    return
  }

  for i, term := range e.AndExpression.Terms {
    if term.getPrecedence() < precedenceAndExpression {
      var b strings.Builder
      b.WriteRune('(')
      b.WriteString(strs[i])
      b.WriteRune(')')
      strs[i] = b.String()
    }
  }

  out = strings.Join(strs, " and ")
  return
}

// Serializes a Range expression.
func (e *Range) Serialize() (out string, err error) {
  var b strings.Builder
  b.WriteRune('(')
  str, err := e.Start.Serialize()
  if err != nil {
    return
  }
  b.WriteString(str)
  b.WriteString("..")

  str, err = e.End.Serialize()
  if err != nil {
    return
  }
  b.WriteString(str)
  b.WriteRune(')')

  out = b.String()
  return
}

// Serializes a for..in expression
func (e *ForInExpression) Serialize() (out string, err error) {
  var b strings.Builder
  b.WriteString("for ")
  str, err := e.ForExpression.Serialize()
  if err != nil {
    return
  }

  b.WriteString(str)
  b.WriteString(" in ")

  str, err = e.IntegerSet.Serialize()
  if err != nil {
    return
  }

  b.WriteString(str)
  b.WriteString(" : (")

  str, err = e.Expression.Serialize()
  if err != nil {
    return
  }

  b.WriteString(str)
  b.WriteRune(')')

  out = b.String()
  return
}

// Serializes a for..of expression
func (e *ForOfExpression) Serialize() (out string, err error) {
  var b strings.Builder
  if e.GetExpression() != nil {
    b.WriteString("for ")
  }
  str, err := e.ForExpression.Serialize()
  if err != nil {
    return
  }

  b.WriteString(str)
  b.WriteString(" of ")

  str, err = e.StringSet.Serialize()
  if err != nil {
    return
  }

  b.WriteString(str)

  if e.GetExpression() != nil {
    b.WriteString(" : (")

    str, err = e.Expression.Serialize()
    if err != nil {
      return
    }
    b.WriteString(str)
    b.WriteRune(')')
  }

  out = b.String()
  return
}

// Serializes a StringSet.
func (e* StringSet) Serialize() (out string, err error) {
  switch e.GetSet().(type) {
  case *StringSet_Strings:
    out, err = e.GetStrings().Serialize()
  case *StringSet_Keyword:
    out, err = e.GetKeyword().Serialize()
  }

  return
}

// Serializes a ForExpression.
func (e *ForExpression) Serialize() (out string, err error) {
  switch e.GetFor().(type) {
  case *ForExpression_Expression:
    out, err = e.GetExpression().Serialize()
  case *ForExpression_Keyword:
    out, err = e.GetKeyword().Serialize()
  }

  return
}

// Serializes a StringEnumeration.
// The returned error must be nil.
func (e *StringEnumeration) Serialize() (out string, _ error) {
  var strs []string
  for _, item := range e.GetItems() {
    strs = append(strs, item.GetStringIdentifier())
  }

  var b strings.Builder
  b.WriteRune('(')
  b.WriteString(strings.Join(strs, ", "))
  b.WriteRune(')')

  out = b.String()
  return
}

// Serializes an IntegerSet.
func (e *IntegerSet) Serialize() (out string, err error) {
  switch e.GetSet().(type) {
  case *IntegerSet_IntegerEnumeration:
    out, err = e.GetIntegerEnumeration().Serialize()
  case *IntegerSet_Range:
    out, err = e.GetRange().Serialize()
  }

  return
}

// Serializes a Keyword.
func (e Keyword) Serialize() (out string, err error) {
  out, ok := keywords[e]
  if !ok {
    err = fmt.Errorf(`Unknown keyword "%v"`, e)
    return
  }

  return
}

// Serializes an IntegerEnumeration.
func (e *IntegerEnumeration) Serialize() (out string, err error) {
  strs, err := mapTermsToStrings(e.Values)
  if err != nil {
    return
  }

  var b strings.Builder
  b.WriteRune('(')
  b.WriteString(strings.Join(strs, ", "))
  b.WriteRune(')')

  out = b.String()
  return
}

// Returns the precedence of a BinaryExpression.
func (e *BinaryExpression) getPrecedence() int8 {
  prec, ok := binaryOperatorsPrecedence[e.GetOperator()]
  if !ok {
    return math.MaxInt8
  }

  return prec
}

// Serializes a BinaryExpression.
func (e *BinaryExpression) Serialize() (out string, err error) {
  var b strings.Builder

  str, err := e.Left.Serialize()
  if err != nil {
    return
  }

  // Left operand
  if (e.Left.getPrecedence() < e.getPrecedence()) {
    b.WriteRune('(')
    b.WriteString(str)
    b.WriteRune(')')
  } else {
    b.WriteString(str)
  }

  // Operator
  b.WriteRune(' ')
  b.WriteString(operators[e.GetOperator()])
  b.WriteRune(' ')

  // Right operand
  str, err = e.Right.Serialize()
  if err != nil {
    return
  }
  if (e.Right.getPrecedence() < e.getPrecedence()) {
    b.WriteRune('(')
    b.WriteString(str)
    b.WriteRune(')')
  } else {
    b.WriteString(str)
  }

  out = b.String()
  return
}

// Serializes an Identifier.
func (i *Identifier) Serialize() (out string, err error) {
  var b strings.Builder
  var str string
  for i, item := range i.GetItems() {
    switch val := item.GetItem().(type) {
    case *Identifier_IdentifierItem_Identifier:
      if i > 0  {
        b.WriteRune('.')
      }
      b.WriteString(item.GetIdentifier())
    case *Identifier_IdentifierItem_Expression:
      b.WriteRune('[')
      str, err = item.GetExpression().Serialize()
      if err != nil {
        return
      }
      b.WriteString(str)
      b.WriteRune(']')
    case *Identifier_IdentifierItem_Arguments:
      var args []string
      for _, arg := range item.GetArguments().Terms {
        str, err = arg.Serialize()
        if err != nil {
          return
        }
        args = append(args, str)
      }

      b.WriteRune('(')
      b.WriteString(strings.Join(args, ","))
      b.WriteRune(')')
    default:
      err = fmt.Errorf(`Unsupported identifier type "%T"`, val)
      return
    }
  }

  out = b.String()
  return
}

// Returns an array with the string representation of the array of Expressions
// provided as an input.
func mapTermsToStrings(expressions []*Expression) (strs []string, err error) {
  for _, expr := range expressions {
    str, err := expr.Serialize()
      if err != nil {
        return nil, err
      }
      strs = append(strs, str)
    }

  return
}

