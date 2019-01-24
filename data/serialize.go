// Functions and methods for reserializing the JSON into YARA rules.

package data

import (
	"fmt"
	"strings"
)

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

	// strs, err := r.Strings.Serialize()
	// if err != nil {
	// 	return
	// }
	// b.WriteString(strs)

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

// TODO Add parenthesis surrounding expressions by checking precedence:
// 1. Define precedences table taking into account the grammar:
//    - Tokens defined later have higher precedence
//    - Tokens in the same %left or %right declaration have the same precedence
// 2. In expressions containing another expression, add parenthesis to those with lower precedence.
func (e *Expression) Serialize() (out string, err error) {
  switch val := e.GetExpression().(type) {
    case *Expression_OrExpression:
      out, err = e.GetOrExpression().Serialize(" or ")
    case *Expression_AndExpression:
      out, err = e.GetAndExpression().Serialize(" and ")
    case *Expression_StringIdentifier:
      out = e.GetStringIdentifier()
    default:
      err = fmt.Errorf(`Unsupported expression type "%T"`, val)
  }

  return
}

func (e *Expressions) Serialize(joinString string) (out string, err error) {
  strs, err := mapTermsToStrings(e)
  if err != nil {
    return
  }

  out = strings.Join(strs, joinString)
  return
}

// // Serialize for BooleanExpressionTerm.
// // Returns the "condition:" section in the YARA rule.
// func (c *BooleanExpressionTerm) Serialize() (out string, err error) {
//   if c == nil {
//     return
//   }
// 
//   if (c.BoolValue != nil) {
//     return fmt.Sprint(*c.BoolValue), nil
//   }
// 
//   if (c.BinaryExpression != nil) {
//     out, err = c.BinaryExpression.Serialize()
//     return
//   }
// 
//   if (c.StringIdentifier != "") {
//     return c.StringIdentifier, nil
//   }
// 
//   if (c.PrimaryExpression != nil) {
//     out, err = c.PrimaryExpression.Serialize()
//     return
//   }
// 
//   if (c.NotExpression != nil) {
//     out, err = c.NotExpression.Serialize()
//     return
//   }
// 
//   if (c.OrExpression != nil) {
//     out, err = c.OrExpression.Serialize()
//     return
//   }
// 
//   if (c.AndExpression != nil) {
//     out, err = c.AndExpression.Serialize()
//     return
//   }
// 
//   return
// }
// 
// func (e *OrExpression) Serialize() (string, error) {
//   strs, err := mapTermsToStrings(*e)
//   if err != nil {
//     return "", err
//   }
// 
//   return strings.Join(strs, " or "), nil
// }
// 
// func (e *AndExpression) Serialize() (string, error) {
//   strs, err := mapTermsToStrings(*e)
//   if err != nil {
//     return "", err
//   }
// 
//   return strings.Join(strs, " and "), nil
// }
// 
func mapTermsToStrings(e *Expressions) (strs []string, err error) {
  for _, expr := range e.Terms {
    str, err := expr.Serialize()
      if err != nil {
        return nil, err
      }
      strs = append(strs, str)
    }

  return
}
// 
// func (e *NotExpression) Serialize() (string, error) {
//   var b strings.Builder
//   b.WriteString("not ")
// 
//   str, err := (*BooleanExpressionTerm)(e).Serialize()
//   if err != nil {
//     return "", err
//   }
//   b.WriteString(str)
// 
//   return b.String(), nil
// }
// 
// func (e *BinaryExpression) Serialize() (out string, err error) {
//   var b strings.Builder
//   var str string
//   if e.Left != nil {
//     str, err = e.Left.Serialize()
//     if err != nil {
//       return
//     }
//     b.WriteString(str)
//   }
// 
//   b.WriteString(" ")
//   b.WriteString(string(e.Operator))
//   b.WriteString(" ")
// 
//   if e.Right != nil {
//     str, err = e.Right.Serialize()
//     if err != nil {
//       return
//     }
//     b.WriteString(str)
//   }
// 
//   return b.String(), nil
// }
// 
// func (o *BinaryExpressionOperand) Serialize() (out string, err error) {
//   if o.PrimaryExpression != nil {
//     out, err = o.PrimaryExpression.Serialize()
//     return
//   }
// 
//   if o.Regexp != nil {
//     out, err = o.Regexp.Serialize()
//     return
//   }
// 
//   if o.StringIdentifier != "" {
//     return o.StringIdentifier, nil
//   }
// 
//   if o.Range != nil {
//     out, err = o.Range.Serialize()
//     return
//   }
// 
//   return
// }
// 
// func (e *PrimaryExpression) Serialize() (out string, err error) {
//     if e == nil {
//       return "", nil
//     }
//     if e.Keyword != "" {
//       return string(e.Keyword), nil
//     }
// 
//     if e.BinaryPrimaryExpression != nil {
//       out, err = e.BinaryPrimaryExpression.Serialize()
//       return
//     }
// 
//     if e.Number != nil {
//       return fmt.Sprintf("%d", *e.Number), nil
//     }
// 
//     if e.Double != nil {
//       return fmt.Sprintf("%f", *e.Double), nil
//     }
// 
//     if e.Text != nil {
//       return *e.Text, nil
//     }
// 
//     if e.StringCount != nil {
//       out, err = e.StringCount.Serialize()
//       return
//     }
// 
//     if e.StringOffset != nil {
//       out, err = e.StringOffset.Serialize()
//       return
//     }
// 
//     if e.StringLength != nil {
//       out, err = e.StringLength.Serialize()
//       return
//     }
// 
//     if e.Identifier != nil {
//       out, err = e.Identifier.Serialize()
//       return
//     }
// 
//     if e.Regexp != nil {
//       out, err = e.Regexp.Serialize()
//       return
//     }
// 
//     return
// }
// 
// func (e *BinaryPrimaryExpression) Serialize() (out string, err error) {
//     var b strings.Builder
//     var str string
//     if e.Left != nil {
//       str, err = e.Left.Serialize()
//       if err != nil {
//         return
//       }
//       b.WriteString(str)
//     }
// 
//     if e.Operator == IntegerFunctionOperator {
//       b.WriteString("(")
//     } else {
//       b.WriteString(" ")
//       b.WriteString(string(e.Operator))
//       b.WriteString(" ")
//     }
// 
//     if e.Right != nil {
//       str, err = e.Right.Serialize()
//       if err != nil {
//         return
//       }
//       b.WriteString(str)
//     }
// 
//     if e.Operator == IntegerFunctionOperator {
//       b.WriteString(")")
//     }
// 
//     return b.String(), nil
// }
// 
// func (o *BinaryPrimaryExpressionOperand) Serialize() (out string, err error) {
//   if o.IntegerFunction != nil {
//     return *o.IntegerFunction, nil
//   }
// 
//   if o.PrimaryExpression != nil {
//     out, err = o.PrimaryExpression.Serialize()
//     return
//   }
// 
//   return
// }
// 
// func (s *StringCount) Serialize() (out string, err error) {
//   return s.StringIdentifier, nil
// }
// 
// func (s *StringOffset) Serialize() (string, error) {
//   var b strings.Builder
//   b.WriteString(s.StringIdentifier)
// 
//   if (s.Index != nil) {
//     b.WriteString("[")
//     str, err := s.Index.Serialize()
//     if err != nil {
//       return "", err
//     }
//     b.WriteString(str)
//     b.WriteString("]")
//   }
// 
//   return b.String(), nil
// }
// 
// func (s *StringLength) Serialize() (string, error) {
//   var b strings.Builder
//   b.WriteString(s.StringIdentifier)
// 
//   if (s.Index != nil) {
//     b.WriteString("[")
//     str, err := s.Index.Serialize()
//     if err != nil {
//       return "", err
//     }
//     b.WriteString(str)
//     b.WriteString("]")
//   }
// 
//   return b.String(), nil
// }
// 
// func (i *Identifier) Serialize() (string, error) {
//   items := []IdentifierItem(*i)
//   var b strings.Builder
//   for i, item := range items {
//     if item.Identifier != "" {
//       if i > 0  {
//         b.WriteString(".")
//       }
//       b.WriteString(item.Identifier)
//     } else if item.PrimaryExpression != nil {
//       b.WriteString("[")
//       str, err := item.PrimaryExpression.Serialize()
//       if err != nil {
//         return "", err
//       }
//       b.WriteString(str)
//       b.WriteString("]")
//     } else if item.Arguments != nil {
//       args := []string{}
//       for _, arg := range item.Arguments {
//         str, err := arg.Serialize()
//         if err != nil {
//           return "", err
//         }
//         args = append(args, str)
//       }
// 
//       b.WriteString("(")
//       b.WriteString(strings.Join(args, ","))
//       b.WriteString(")")
//     }
//   }
// 
//   return b.String(), nil
// }
// 
// func (r *Range) Serialize() (string, error) {
//   var b strings.Builder
//   str, err := r.Start.Serialize()
//   if err != nil {
//     return "", err
//   }
//   b.WriteString(str)
// 
//   b.WriteString("..")
// 
//   str, err = r.End.Serialize()
//   if err != nil {
//     return "", err
//   }
//   b.WriteString(str)
// 
//   return b.String(), nil
// }
// 
// func (r *Regexp) Serialize() (string, error) {
//   var b strings.Builder
//   b.WriteString("/")
//   b.WriteString(r.Text)
//   b.WriteString("/")
// 
//   if (r.Modifiers.I) {
//     b.WriteString("i")
//   }
//   if (r.Modifiers.S) {
//     b.WriteString("s")
//   }
// 
//   return b.String(), nil
// }
// 
// 
// 
// // Serialize for Strings returns the "strings:" section in the YARA rule
// func (ss *Strings) Serialize() (out string, err error) {
// 	if ss == nil || len(*ss) == 0 {
// 		return
// 	}
// 
// 	var b strings.Builder
// 	b.WriteString("strings:\n")
// 
// 	for _, s := range *ss {
// 		str, e := s.Serialize()
// 		if e != nil {
// 			err = e
// 			return
// 		}
// 		b.WriteString("  ") // TODO: Make indent customizable
// 		b.WriteString(str)
// 		b.WriteRune('\n')
// 	}
// 
// 	out = b.String()
// 	return
// }
// 
// // Serialize for String returns a String as a string
// func (s *String) Serialize() (out string, err error) {
// 	// Format string for:
// 	// `<identifier> = <encapsOpen> <text> <encapsClose> <modifiers>`
// 	format := "%s = %s%s%s %s"
// 
// 	var (
// 		encapsOpen  string
// 		encapsClose string
// 	)
// 	switch t := s.Type; t {
// 	case TypeString:
// 		encapsOpen, encapsClose = `"`, `"`
// 
// 	case TypeHexString:
// 		encapsOpen, encapsClose = "{", "}"
// 
// 	case TypeRegex:
// 		encapsOpen = "/"
// 		var closeBuilder strings.Builder
// 		closeBuilder.WriteRune('/')
// 		if s.Modifiers.I {
// 			closeBuilder.WriteRune('i')
// 		}
// 		if s.Modifiers.S {
// 			closeBuilder.WriteRune('s')
// 		}
// 		encapsClose = closeBuilder.String()
// 
// 	default:
// 		err = fmt.Errorf("No such string type %s (%d)", t, t)
// 		return
// 	}
// 
// 	mods, _ := s.Modifiers.Serialize()
// 
// 	out = fmt.Sprintf(format, s.ID, encapsOpen, s.Text, encapsClose, mods)
// 
// 	return
// }
// 
// // Serialize for StringModifiers creates a space-sparated list of
// // string modifiers, excluding the i and s which are appended to /regex/
// // The returned error must be nil.
// func (m *StringModifiers) Serialize() (out string, _ error) {
// 	const modsAvailable = 4
// 	modifiers := make([]string, 0, modsAvailable)
// 	if m.ASCII {
// 		modifiers = append(modifiers, "ascii")
// 	}
// 	if m.Wide {
// 		modifiers = append(modifiers, "wide")
// 	}
// 	if m.Nocase {
// 		modifiers = append(modifiers, "nocase")
// 	}
// 	if m.Fullword {
// 		modifiers = append(modifiers, "fullword")
// 	}
// 	if m.Xor {
// 		modifiers = append(modifiers, "xor")
// 	}
// 
// 	out = strings.Join(modifiers, " ")
// 	return
// }
