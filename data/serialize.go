// Functions and methods for serializing a RuleSet proto to YARA rules as strings.

package data

import (
	"fmt"
	"math"
	"strings"
)

// YaraSerializer converts a RuleSet from proto to YARA ruleset.
// Contains configuration options.
type YaraSerializer struct {
	// Indentation string.
	Indent string
}

// Serialize converts the provided RuleSet proto to a YARA ruleset.
func (s YaraSerializer) Serialize(rs RuleSet) (string, error) {
	return s.serializeRuleSet(&rs)
}

var keywords = map[Keyword]string{
	Keyword_ENTRYPOINT: "entrypoint",
	Keyword_FILESIZE:   "filesize",
	Keyword_THEM:       "them",
	Keyword_ALL:        "all",
	Keyword_ANY:        "any",
}

var operators = map[BinaryExpression_Operator]string{
	BinaryExpression_MATCHES:     "matches",
	BinaryExpression_CONTAINS:    "contains",
	BinaryExpression_AT:          "at",
	BinaryExpression_IN:          "in",
	BinaryExpression_BITWISE_OR:  "|",
	BinaryExpression_XOR:         "^",
	BinaryExpression_BITWISE_AND: "&",
	BinaryExpression_EQ:          "==",
	BinaryExpression_NEQ:         "!=",
	BinaryExpression_LT:          "<",
	BinaryExpression_LE:          "<=",
	BinaryExpression_GT:          ">",
	BinaryExpression_GE:          ">=",
	BinaryExpression_SHIFT_LEFT:  "<<",
	BinaryExpression_SHIFT_RIGHT: ">>",
	BinaryExpression_PLUS:        "+",
	BinaryExpression_MINUS:       "-",
	BinaryExpression_TIMES:       "*",
	BinaryExpression_DIV:         "\\",
	BinaryExpression_MOD:         "%",
}

const precedenceOrExpression int8 = 1
const precedenceAndExpression int8 = 2

// Operators AT, IN, MATCHES and CONTAINS do not have a specified precedence.
// In those cases, the maximum precedence value should be assumed to prevent
// adding unnecessary parenthesis.
var binaryOperatorsPrecedence = map[BinaryExpression_Operator]int8{
	BinaryExpression_BITWISE_OR:  3,
	BinaryExpression_XOR:         4,
	BinaryExpression_BITWISE_AND: 5,
	BinaryExpression_EQ:          6,
	BinaryExpression_NEQ:         6,
	BinaryExpression_LT:          7,
	BinaryExpression_LE:          7,
	BinaryExpression_GT:          7,
	BinaryExpression_GE:          7,
	BinaryExpression_SHIFT_LEFT:  8,
	BinaryExpression_SHIFT_RIGHT: 8,
	BinaryExpression_PLUS:        9,
	BinaryExpression_MINUS:       9,
	BinaryExpression_TIMES:       10,
	BinaryExpression_DIV:         10,
	BinaryExpression_MOD:         10,
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
	default:
		// Expression with no precedence defined. Return maximum value.
		return math.MaxInt8
	}
}

// Serializes a complete YARA ruleset.
func (s YaraSerializer) serializeRuleSet(rs *RuleSet) (out string, err error) {
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
		str, err := s.serializeRule(rule)
		if err != nil {
			return "", err
		}
		b.WriteString(str)
	}

	out = b.String()
	return
}

// Serializes a YARA rule.
func (s YaraSerializer) serializeRule(r *Rule) (out string, err error) {
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

	metas, err := s.serializeMetas(r.Meta)
	if err != nil {
		return
	}
	b.WriteString(metas)

	strs, err := s.serializeStrings(r.Strings)
	if err != nil {
		return
	}
	b.WriteString(strs)

	b.WriteString(s.getIndentation(1))
	b.WriteString("condition:\n")
	b.WriteString(s.getIndentation(2))
	str, err := s.serializeExpression(r.Condition)
	if err != nil {
		return
	}
	b.WriteString(str)
	b.WriteString("\n}\n\n")

	out = b.String()
	return
}

func (s YaraSerializer) getIndentation(level int) string {
	return strings.Repeat(s.Indent, level)
}

// Serializes the "meta:" section in a YARA rule.
func (s YaraSerializer) serializeMetas(ms []*Meta) (out string, err error) {
	if ms == nil || len(ms) == 0 {
		return
	}

	var b strings.Builder
	b.WriteString(s.getIndentation(1))
	b.WriteString("meta:\n")

	for _, m := range ms {
		meta, e := s.serializeMeta(m)
		if e != nil {
			err = e
			return
		}
		b.WriteString(s.getIndentation(2))
		b.WriteString(meta)
		b.WriteRune('\n')
	}

	out = b.String()
	return
}

// Serializes a Meta declaration (key/value pair) in a YARA rule.
func (s YaraSerializer) serializeMeta(m *Meta) (out string, err error) {
	switch val := m.GetValue().(type) {
	case *Meta_Text:
		out = fmt.Sprintf(`%s = "%s"`, m.GetKey(), m.GetText())
	case *Meta_Number:
		out = fmt.Sprintf(`%s = %v`, m.GetKey(), m.GetNumber())
	case *Meta_Boolean:
		out = fmt.Sprintf(`%s = %v`, m.GetKey(), m.GetBoolean())
	default:
		err = fmt.Errorf(`Unsupported Meta value type "%s"`, val)
		return
	}

	return
}

// Serializes the "strings:" section in a YARA rule.
func (s YaraSerializer) serializeStrings(strs []*String) (out string, err error) {
	if strs == nil || len(strs) == 0 {
		return
	}

	var b strings.Builder
	b.WriteString(s.getIndentation(1))
	b.WriteString("strings:\n")

	for _, str := range strs {
		serializedStr, e := s.serializeString(str)
		if e != nil {
			err = e
			return
		}

		b.WriteString(s.getIndentation(2))
		b.WriteString(serializedStr)
		b.WriteRune('\n')
	}

	out = b.String()
	return
}

// Serialize for String returns a String as a string
func (s YaraSerializer) serializeString(str *String) (out string, err error) {
	// Format string for:
	// `<identifier> = <encapsOpen> <text> <encapsClose> <modifiers>`
	format := "%s = %s%s%s %s"

	var (
		encapsOpen  string
		encapsClose string
	)
	switch val := str.GetType(); val {
	case String_TEXT:
		encapsOpen, encapsClose = `"`, `"`
	case String_HEX:
		encapsOpen, encapsClose = "{", "}"
	case String_REGEX:
		encapsOpen = "/"
		var closeBuilder strings.Builder
		closeBuilder.WriteRune('/')
		if str.Modifiers.GetI() {
			closeBuilder.WriteRune('i')
		}
		if str.Modifiers.GetS() {
			closeBuilder.WriteRune('s')
		}
		encapsClose = closeBuilder.String()
	default:
		err = fmt.Errorf("Unsupported String type %s (%d)", val, val)
		return
	}

	mods, _ := s.serializeStringModifiers(str.Modifiers)
	out = strings.TrimSpace(fmt.Sprintf(format, str.GetId(), encapsOpen, str.GetText(), encapsClose, mods))
	return
}

// Serialize for StringModifiers creates a space-sparated list of
// string modifiers, excluding the i and s which are appended to /regex/
// The returned error must be nil.
func (s YaraSerializer) serializeStringModifiers(m *StringModifiers) (out string, _ error) {
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
func (s YaraSerializer) serializeExpression(e *Expression) (out string, err error) {
	switch val := e.GetExpression().(type) {
	case *Expression_BoolValue:
		out = fmt.Sprintf("%v", e.GetBoolValue())
	case *Expression_OrExpression:
		return s.serializeOrExpression(e.GetOrExpression())
	case *Expression_AndExpression:
		return s.serializeAndExpression(e.GetAndExpression())
	case *Expression_StringIdentifier:
		out = e.GetStringIdentifier()
	case *Expression_ForInExpression:
		return s.serializeForInExpression(e.GetForInExpression())
	case *Expression_ForOfExpression:
		return s.serializeForOfExpression(e.GetForOfExpression())
	case *Expression_BinaryExpression:
		return s.serializeBinaryExpression(e.GetBinaryExpression())
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
		return s.serializeRange(e.GetRange())
	case *Expression_Keyword:
		return s.serializeKeyword(e.GetKeyword())
	case *Expression_Identifier:
		return s.serializeIdentifier(e.GetIdentifier())
	case *Expression_Regexp:
		return s.serializeRegexp(e.GetRegexp())
	case *Expression_NotExpression:
		return s.serializeNotExpression(e.GetNotExpression())
	case *Expression_IntegerFunction:
		return s.serializeIntegerFunction(e.GetIntegerFunction())
	case *Expression_StringOffset:
		return s.serializeStringOffset(e.GetStringOffset())
	case *Expression_StringLength:
		return s.serializeStringLength(e.GetStringLength())
	case *Expression_StringCount:
		out = e.GetStringCount()
	default:
		err = fmt.Errorf(`Unsupported Expression type "%T"`, val)
		return
	}

	return
}

// Serializes an OR expression.
func (s YaraSerializer) serializeOrExpression(es *Expressions) (out string, err error) {
	strs, err := s.mapTermsToStrings(es.Terms)
	if err != nil {
		return
	}

	out = strings.Join(strs, " or ")
	return
}

// Serializes an AND expression.
func (s YaraSerializer) serializeAndExpression(e *Expressions) (out string, err error) {
	strs, err := s.mapTermsToStrings(e.Terms)
	if err != nil {
		return
	}

	for i, term := range e.Terms {
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

// Serializes a for..in expression
func (s YaraSerializer) serializeForInExpression(e *ForInExpression) (out string, err error) {
	var b strings.Builder
	b.WriteString("for ")
	str, err := s.serializeForExpression(e.ForExpression)
	if err != nil {
		return
	}
	b.WriteString(str)

	b.WriteRune(' ')
	b.WriteString(e.GetIdentifier())

	b.WriteString(" in ")

	str, err = s.serializeIntegerSet(e.IntegerSet)
	if err != nil {
		return
	}

	b.WriteString(str)
	b.WriteString(" : (")

	str, err = s.serializeExpression(e.Expression)
	if err != nil {
		return
	}

	b.WriteString(str)
	b.WriteRune(')')

	out = b.String()
	return
}

// Serializes a ForExpression.
func (s YaraSerializer) serializeForExpression(e *ForExpression) (out string, err error) {
	switch val := e.GetFor().(type) {
	case *ForExpression_Expression:
		return s.serializeExpression(e.GetExpression())
	case *ForExpression_Keyword:
		return s.serializeKeyword(e.GetKeyword())
	default:
		err = fmt.Errorf(`Unsupported ForExpression value type "%s"`, val)
		return
	}

	return
}

// Serializes an IntegerSet.
func (s YaraSerializer) serializeIntegerSet(e *IntegerSet) (out string, err error) {
	switch val := e.GetSet().(type) {
	case *IntegerSet_IntegerEnumeration:
		return s.serializeIntegerEnumeration(e.GetIntegerEnumeration())
	case *IntegerSet_Range:
		return s.serializeRange(e.GetRange())
	default:
		err = fmt.Errorf(`Unsupported IntegerSet value type "%s"`, val)
		return
	}

	return
}

// Serializes an IntegerEnumeration.
func (s YaraSerializer) serializeIntegerEnumeration(e *IntegerEnumeration) (out string, err error) {
	strs, err := s.mapTermsToStrings(e.Values)
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

// Serializes a Range expression.
func (s YaraSerializer) serializeRange(e *Range) (out string, err error) {
	var b strings.Builder
	b.WriteRune('(')
	str, err := s.serializeExpression(e.Start)
	if err != nil {
		return
	}
	b.WriteString(str)
	b.WriteString("..")

	str, err = s.serializeExpression(e.End)
	if err != nil {
		return
	}
	b.WriteString(str)
	b.WriteRune(')')

	out = b.String()
	return
}

// Serializes a for..of expression
func (s YaraSerializer) serializeForOfExpression(e *ForOfExpression) (out string, err error) {
	var b strings.Builder
	if e.GetExpression() != nil {
		b.WriteString("for ")
	}
	str, err := s.serializeForExpression(e.ForExpression)
	if err != nil {
		return
	}

	b.WriteString(str)
	b.WriteString(" of ")

	str, err = s.serializeStringSet(e.StringSet)
	if err != nil {
		return
	}

	b.WriteString(str)

	if e.GetExpression() != nil {
		b.WriteString(" : (")

		str, err = s.serializeExpression(e.Expression)
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
func (s YaraSerializer) serializeStringSet(e *StringSet) (out string, err error) {
	switch e.GetSet().(type) {
	case *StringSet_Strings:
		return s.serializeStringEnumeration(e.GetStrings())
	case *StringSet_Keyword:
		return s.serializeKeyword(e.GetKeyword())
	}

	return
}

// Serializes a StringEnumeration.
// The returned error must be nil.
func (s YaraSerializer) serializeStringEnumeration(e *StringEnumeration) (out string, _ error) {
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

// Serializes a Keyword.
func (s YaraSerializer) serializeKeyword(e Keyword) (out string, err error) {
	out, ok := keywords[e]
	if !ok {
		err = fmt.Errorf(`Unknown keyword "%v"`, e)
	}

	return
}

// Serializes a BinaryExpression.
func (s YaraSerializer) serializeBinaryExpression(e *BinaryExpression) (out string, err error) {
	var b strings.Builder

	// Left operand
	str, err := s.serializeExpression(e.Left)
	if err != nil {
		return
	}
	if e.Left.getPrecedence() < e.getPrecedence() {
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
	str, err = s.serializeExpression(e.Right)
	if err != nil {
		return
	}
	if e.Right.getPrecedence() < e.getPrecedence() {
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
func (s YaraSerializer) serializeIdentifier(i *Identifier) (out string, err error) {
	var b strings.Builder
	var str string
	for i, item := range i.GetItems() {
		switch val := item.GetItem().(type) {
		case *Identifier_IdentifierItem_Identifier:
			if i > 0 {
				b.WriteRune('.')
			}
			b.WriteString(item.GetIdentifier())
		case *Identifier_IdentifierItem_Expression:
			b.WriteRune('[')
			str, err = s.serializeExpression(item.GetExpression())
			if err != nil {
				return
			}
			b.WriteString(str)
			b.WriteRune(']')
		case *Identifier_IdentifierItem_Arguments:
			var args []string
			for _, arg := range item.GetArguments().Terms {
				str, err = s.serializeExpression(arg)
				if err != nil {
					return
				}
				args = append(args, str)
			}

			b.WriteRune('(')
			b.WriteString(strings.Join(args, ", "))
			b.WriteRune(')')
		default:
			err = fmt.Errorf(`Unsupported identifier type "%T"`, val)
			return
		}
	}

	out = b.String()
	return
}

// Serializes a Regexp, appending the i and s modifiers if included.
// The returned error must be nil.
func (s YaraSerializer) serializeRegexp(r *Regexp) (out string, _ error) {
	var b strings.Builder
	b.WriteRune('/')
	b.WriteString(r.GetText())
	b.WriteRune('/')

	if r.Modifiers.GetI() {
		b.WriteRune('i')
	}
	if r.Modifiers.GetS() {
		b.WriteRune('s')
	}

	out = b.String()
	return
}

// Serializes a NOT expression.
func (s YaraSerializer) serializeNotExpression(e *Expression) (out string, err error) {
	var b strings.Builder
	b.WriteString("not ")
	str, err := s.serializeExpression(e)
	if err != nil {
		return
	}

	if e.getPrecedence() < precedenceNotExpression {
		b.WriteRune('(')
		b.WriteString(str)
		b.WriteRune(')')
	} else {
		b.WriteString(str)
	}

	out = b.String()
	return
}

// Serializes an IntegerFunction.
func (s YaraSerializer) serializeIntegerFunction(e *IntegerFunction) (out string, err error) {
	var b strings.Builder
	b.WriteString(e.GetFunction())
	b.WriteRune('(')
	str, err := s.serializeExpression(e.GetExpression())
	if err != nil {
		return
	}
	b.WriteString(str)
	b.WriteRune(')')

	out = b.String()
	return
}

// Serializes a StringOffset.
func (s YaraSerializer) serializeStringOffset(e *StringOffset) (out string, err error) {
	var b strings.Builder
	b.WriteString(e.GetStringIdentifier())
	if e.GetIndex() != nil {
		b.WriteRune('[')
		var str string
		str, err = s.serializeExpression(e.GetIndex())
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
func (s YaraSerializer) serializeStringLength(e *StringLength) (out string, err error) {
	var b strings.Builder
	b.WriteString(e.GetStringIdentifier())
	if e.GetIndex() != nil {
		b.WriteRune('[')
		var str string
		str, err = s.serializeExpression(e.GetIndex())
		if err != nil {
			return
		}
		b.WriteString(str)
		b.WriteRune(']')
	}

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

// Returns an array with the string representation of the array of Expressions
// provided as an input.
func (s YaraSerializer) mapTermsToStrings(expressions []*Expression) (strs []string, err error) {
	for _, expr := range expressions {
		str, err := s.serializeExpression(expr)
		if err != nil {
			return nil, err
		}
		strs = append(strs, str)
	}

	return
}
