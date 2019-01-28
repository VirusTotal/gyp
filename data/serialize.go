// Functions and methods for reserializing the JSON into YARA rules.

package data

import (
	"fmt"
	"strings"
)

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

const precedenceOr = 1
const precedenceAnd = 2

var binaryOperatorsPrecedence = map[BinaryExpression_Operator]int {
  BinaryExpression_AT: 3,
  BinaryExpression_IN: 4,
  BinaryExpression_MATCHES: 5,
  BinaryExpression_CONTAINS: 6,
  BinaryExpression_BITWISE_OR: 7,
  BinaryExpression_XOR: 8,
  BinaryExpression_BITWISE_AND: 9,
  BinaryExpression_EQ: 10,
  BinaryExpression_NEQ: 10,
  BinaryExpression_LT: 11,
  BinaryExpression_LE: 11,
  BinaryExpression_GT: 11,
  BinaryExpression_GE: 11,
  BinaryExpression_SHIFT_LEFT: 12,
  BinaryExpression_SHIFT_RIGHT: 12,
  BinaryExpression_PLUS: 13,
  BinaryExpression_MINUS: 13,
  BinaryExpression_TIMES: 14,
  BinaryExpression_DIV: 14,
  BinaryExpression_MOD: 14,
}

const precedenceNot = 15

func (e *Expression) getPrecedence() int {
  switch e.GetExpression().(type) {
  case *Expression_OrExpression:
    return precedenceOr
  case *Expression_AndExpression:
    return precedenceAnd
  case *Expression_BinaryExpression:
    return binaryOperatorsPrecedence[e.GetBinaryExpression().GetOperator()]
  case *Expression_NotExpression:
    return precedenceNot
  case *Expression_UnaryExpression:
    return precedenceNot
  }

  return precedenceNot + 1
}

// Serialize for RuleSet builds a complete YARA ruleset
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

// Serialize for Rule builds a YARA rule as a string
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

// Returns the "meta:" section in the YARA rule
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

// Serialize for Meta returns the string representation of the key/value pair
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
 	}
 
 	return
}

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
    b.WriteString("\n")
  }

  out = b.String()
  return
}

func (r *Regexp) Serialize() (string, error) {
  var b strings.Builder
  b.WriteString("/")
  b.WriteString(r.GetText())
  b.WriteString("/")

  if (r.Modifiers.GetI()) {
    b.WriteString("i")
  }
  if (r.Modifiers.GetS()) {
    b.WriteString("s")
  }

  return b.String(), nil
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

func (e *Expression) Serialize() (out string, err error) {
  switch val := e.GetExpression().(type) {
  case *Expression_OrExpression:
    or := e.GetExpression().(*Expression_OrExpression)
    out, err = or.Serialize()
  case *Expression_AndExpression:
    and := e.GetExpression().(*Expression_AndExpression)
    out, err = and.Serialize()
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
  }

  return
}

func (e *StringOffset) Serialize() (out string, err error) {
  var b strings.Builder
  b.WriteString(e.GetStringIdentifier())
  if (e.GetIndex() != nil) {
    b.WriteString("[")
    var str string
    str, err = e.GetIndex().Serialize()
    if err != nil {
      return
    }
    b.WriteString(str)
    b.WriteString("]")
  }

  out = b.String()
  return
}

func (e *StringLength) Serialize() (out string, err error) {
  var b strings.Builder
  b.WriteString(e.GetStringIdentifier())
  if (e.GetIndex() != nil) {
    b.WriteString("[")
    var str string
    str, err = e.GetIndex().Serialize()
    if err != nil {
      return
    }
    b.WriteString(str)
    b.WriteString("]")
  }

  out = b.String()
  return
}

func (e *IntegerFunction) Serialize() (out string, err error) {
  var b strings.Builder
  b.WriteString(e.GetFunction())
  b.WriteString("(")
  str, err := e.GetExpression().Serialize()
  if err != nil {
    return
  }
  b.WriteString(str)
  b.WriteString(")")

  out = b.String()
  return
}

func (e *Expression_NotExpression) Serialize() (out string, err error) {
  var b strings.Builder
  b.WriteString("not ")
  str, err := e.NotExpression.Serialize()
  if err != nil {
    return
  }

  if (e.NotExpression.getPrecedence() < precedenceNot) {
    b.WriteString("(")
    b.WriteString(str)
    b.WriteString(")")
  } else {
    b.WriteString(str)
  }
  out = b.String()
  return
}

func (e *Expression_OrExpression) Serialize() (out string, err error) {
  strs, err := mapTermsToStrings(e.OrExpression.Terms)
  if err != nil {
    return
  }

  out = strings.Join(strs, " or ")
  return
}

func (e *Expression_AndExpression) Serialize() (out string, err error) {
  strs, err := mapTermsToStrings(e.AndExpression.Terms)
  if err != nil {
    return
  }

  for i, term := range e.AndExpression.Terms {
    switch term.GetExpression().(type) {
    case *Expression_OrExpression:
      var b strings.Builder
      b.WriteString("(")
      b.WriteString(strs[i])
      b.WriteString(")")
      strs[i] = b.String()
    }
  }

  out = strings.Join(strs, " and ")
  return
}

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

func (e* StringSet) Serialize() (out string, err error) {
  switch e.GetSet().(type) {
  case *StringSet_Strings:
    out, err = e.GetStrings().Serialize()
  case *StringSet_Keyword:
    out, err = e.GetKeyword().Serialize()
  }

  return
}

func (e *ForExpression) Serialize() (out string, err error) {
  switch e.GetFor().(type) {
  case *ForExpression_Expression:
    out, err = e.GetExpression().Serialize()
  case *ForExpression_Keyword:
    out, err = e.GetKeyword().Serialize()
  }

  return
}

func (e *StringEnumeration) Serialize() (out string, err error) {
  var strs []string
  for _, item := range e.GetItems() {
    itemStr := item.GetStringIdentifier()
    if (item.GetHasWildcard()) {
      itemStr += "*"
    }

    strs = append(strs, itemStr)
  }

  var b strings.Builder
  b.WriteString("(")
  b.WriteString(strings.Join(strs, ", "))
  b.WriteString(")")
  out = b.String()
  return
}

func (e *IntegerSet) Serialize() (out string, err error) {
  switch e.GetSet().(type) {
  case *IntegerSet_IntegerEnumeration:
    out, err = e.GetIntegerEnumeration().Serialize()
  case *IntegerSet_Range:
    out, err = e.GetRange().Serialize()
  }

  return
}

func (e Keyword) Serialize() (out string, err error) {
  switch e {
  case Keyword_ENTRYPOINT:
    out = "entrypoint"
  case Keyword_FILESIZE:
    out = "filesize"
  case Keyword_THEM:
    out = "them"
  case Keyword_ALL:
    out = "all"
  case Keyword_ANY:
    out = "any"
  }

  return
}

func (e *IntegerEnumeration) Serialize() (out string, err error) {
  strs, err := mapTermsToStrings(e.Values)
  if err != nil {
    return
  }

  var b strings.Builder
  b.WriteString("(")
  b.WriteString(strings.Join(strs, ", "))
  b.WriteString(")")
  out = b.String()
  return
}

func (e *BinaryExpression) getPrecedence() int {
  return binaryOperatorsPrecedence[e.GetOperator()]
}

func (e *BinaryExpression) Serialize() (out string, err error) {
  var b strings.Builder

  // Left expression. If it's a binary expression and has less precedence, enclose it in params
  str, err := e.Left.Serialize()
  if err != nil {
    return
  }

  if (e.Left.getPrecedence() < e.getPrecedence()) {
    b.WriteString("(")
    b.WriteString(str)
    b.WriteString(")")
  } else {
    b.WriteString(str)
  }

  // Operator
  b.WriteRune(' ')
  b.WriteString(operators[e.GetOperator()])
  b.WriteRune(' ')

  // Right expression. If it's a binary expression and has less precedence, enclose it in params
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
      b.WriteRune('(')
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

