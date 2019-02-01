// Functions and methods for serializing a RuleSet proto to YARA rules as strings.

package yara

import (
	"fmt"
	"io"
	"math"
	"strings"
)

// YaraSerializer converts a RuleSet from proto to YARA ruleset.
// Contains configuration options.
type YaraSerializer struct {
	// Indentation string.
	Indent string

	w io.Writer
}

func CreateYaraSerializer(indent string, w io.Writer) *YaraSerializer {
	return &YaraSerializer{Indent: indent, w: w}
}

// Serialize converts the provided RuleSet proto to a YARA ruleset.
func (ys *YaraSerializer) Serialize(rs RuleSet) error {
	return ys.serializeRuleSet(&rs)
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
func (ys *YaraSerializer) serializeRuleSet(rs *RuleSet) error {
	if len(rs.Includes) > 0 {
		for _, include := range rs.Includes {
			if err := ys.writeString(fmt.Sprintf("include \"%s\"\n", include)); err != nil {
				return err
			}
		}

		if err := ys.writeString("\n"); err != nil {
			return err
		}
	}

	if len(rs.Imports) > 0 {
		for _, imp := range rs.Imports {
			if err := ys.writeString(fmt.Sprintf("import \"%s\"\n", imp)); err != nil {
				return err
			}
		}

		if err := ys.writeString("\n"); err != nil {
			return err
		}
	}

	for _, rule := range rs.Rules {
		if err := ys.serializeRule(rule); err != nil {
			return err
		}
	}

	return nil
}

// Serializes a YARA rule.
func (ys *YaraSerializer) serializeRule(r *Rule) error {
	// Rule modifiers
	if r.Modifiers.GetGlobal() {
		if err := ys.writeString("global "); err != nil {
			return err
		}
	}
	if r.Modifiers.GetPrivate() {
		if err := ys.writeString("private "); err != nil {
			return err
		}
	}

	// Rule name
	if err := ys.writeString(fmt.Sprintf("rule %s ", r.GetIdentifier())); err != nil {
		return err
	}

	// Any applicable tags
	if len(r.Tags) > 0 {
		if err := ys.writeString(": "); err != nil {
			return err
		}
		for _, t := range r.Tags {
			if err := ys.writeString(t); err != nil {
				return err
			}
			if err := ys.writeString(" "); err != nil {
				return err
			}
		}
	}

	// Start metas, strings, etc.
	if err := ys.writeString("{\n"); err != nil {
		return err
	}

	if err := ys.serializeMetas(r.Meta); err != nil {
		return err
	}

	if err := ys.serializeStrings(r.Strings); err != nil {
		return err
	}

	if err := ys.indent(1); err != nil {
		return err
	}

	if err := ys.writeString("condition:\n"); err != nil {
		return err
	}

	if err := ys.indent(2); err != nil {
		return err
	}

	if err := ys.serializeExpression(r.Condition); err != nil {
		return err
	}

	if err := ys.writeString("\n}\n\n"); err != nil {
		return err
	}

	return nil
}

// Serializes the "meta:" section in a YARA rule.
func (ys *YaraSerializer) serializeMetas(ms []*Meta) error {
	if ms == nil || len(ms) == 0 {
		return nil
	}

	if err := ys.indent(1); err != nil {
		return err
	}

	if err := ys.writeString("meta:\n"); err != nil {
		return err
	}

	for _, m := range ms {
		if err := ys.indent(2); err != nil {
			return err
		}
		if err := ys.serializeMeta(m); err != nil {
			return err
		}
		if err := ys.writeString("\n"); err != nil {
			return err
		}
	}

	return nil
}

// Serializes a Meta declaration (key/value pair) in a YARA rule.
func (ys *YaraSerializer) serializeMeta(m *Meta) error {
	switch val := m.GetValue().(type) {
	case *Meta_Text:
		return ys.writeString(fmt.Sprintf(`%s = "%s"`, m.GetKey(), m.GetText()))
	case *Meta_Number:
		return ys.writeString(fmt.Sprintf(`%s = %v`, m.GetKey(), m.GetNumber()))
	case *Meta_Boolean:
		return ys.writeString(fmt.Sprintf(`%s = %v`, m.GetKey(), m.GetBoolean()))
	default:
		return fmt.Errorf(`Unsupported Meta value type "%s"`, val)
	}
}

// Serializes the "strings:" section in a YARA rule.
func (ys *YaraSerializer) serializeStrings(strs []*String) error {
	if strs == nil || len(strs) == 0 {
		return nil
	}

	if err := ys.indent(1); err != nil {
		return err
	}

	if err := ys.writeString("strings:\n"); err != nil {
		return err
	}

	for _, str := range strs {
		if err := ys.indent(2); err != nil {
			return err
		}
		if err := ys.serializeString(str); err != nil {
			return err
		}
		if err := ys.writeString("\n"); err != nil {
			return err
		}
	}

	return nil
}

// Serialize for String returns a String as a string
func (ys *YaraSerializer) serializeString(str *String) error {
	// Format string for:
	// `<identifier> = <encapsOpen> <text> <encapsClose>`
	format := "%s = %s%s%s"

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
		return fmt.Errorf("Unsupported String type %s (%d)", val, val)
	}

	if err := ys.writeString(fmt.Sprintf(format, str.GetId(), encapsOpen, str.GetText(), encapsClose)); err != nil {
		return err
	}

	return ys.serializeStringModifiers(str.Modifiers)
}

// Serialize for StringModifiers creates a space-sparated list of
// string modifiers, excluding the i and s which are appended to /regex/
func (ys *YaraSerializer) serializeStringModifiers(m *StringModifiers) error {
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

	if len(modifiers) == 0 {
		return nil
	}

	if err := ys.writeString(" "); err != nil {
		return err
	}

	return ys.writeString(strings.Join(modifiers, " "))
}

// Serializes an Expression in a YARA rule condition.
func (ys *YaraSerializer) serializeExpression(e *Expression) error {
	switch val := e.GetExpression().(type) {
	case *Expression_BoolValue:
		return ys.writeString(fmt.Sprintf("%v", e.GetBoolValue()))
	case *Expression_OrExpression:
		return ys.serializeOrExpression(e.GetOrExpression())
	case *Expression_AndExpression:
		return ys.serializeAndExpression(e.GetAndExpression())
	case *Expression_StringIdentifier:
		return ys.writeString(e.GetStringIdentifier())
	case *Expression_ForInExpression:
		return ys.serializeForInExpression(e.GetForInExpression())
	case *Expression_ForOfExpression:
		return ys.serializeForOfExpression(e.GetForOfExpression())
	case *Expression_BinaryExpression:
		return ys.serializeBinaryExpression(e.GetBinaryExpression())
	case *Expression_Text:
		if err := ys.writeString(`"`); err != nil {
			return err
		}
		if err := ys.writeString(e.GetText()); err != nil {
			return err
		}
		if err := ys.writeString(`"`); err != nil {
			return err
		}
		return nil
	case *Expression_NumberValue:
		return ys.writeString(fmt.Sprintf("%d", e.GetNumberValue()))
	case *Expression_DoubleValue:
		return ys.writeString(fmt.Sprintf("%f", e.GetDoubleValue()))
	case *Expression_Range:
		return ys.serializeRange(e.GetRange())
	case *Expression_Keyword:
		return ys.serializeKeyword(e.GetKeyword())
	case *Expression_Identifier:
		return ys.serializeIdentifier(e.GetIdentifier())
	case *Expression_Regexp:
		return ys.serializeRegexp(e.GetRegexp())
	case *Expression_NotExpression:
		return ys.serializeNotExpression(e.GetNotExpression())
	case *Expression_IntegerFunction:
		return ys.serializeIntegerFunction(e.GetIntegerFunction())
	case *Expression_StringOffset:
		return ys.serializeStringOffset(e.GetStringOffset())
	case *Expression_StringLength:
		return ys.serializeStringLength(e.GetStringLength())
	case *Expression_StringCount:
		return ys.writeString(e.GetStringCount())
	default:
		return fmt.Errorf(`Unsupported Expression type "%T"`, val)
	}
}

// Serializes an OR expression.
func (ys *YaraSerializer) serializeOrExpression(es *Expressions) error {
	return ys.serializeTerms(es.Terms, " or ", precedenceOrExpression)
}

// Serializes an AND expression.
func (ys *YaraSerializer) serializeAndExpression(es *Expressions) error {
	return ys.serializeTerms(es.Terms, " and ", precedenceAndExpression)
}

func (ys *YaraSerializer) serializeTerms(terms []*Expression, joinStr string, precedence int8) error {
	for i, term := range terms {
		addParens := term.getPrecedence() < precedenceAndExpression
		if addParens {
			if err := ys.writeString("("); err != nil {
				return err
			}
		}

		if err := ys.serializeExpression(term); err != nil {
			return err
		}

		if addParens {
			if err := ys.writeString(")"); err != nil {
				return err
			}
		}

		if i < len(terms)-1 {
			if err := ys.writeString(joinStr); err != nil {
				return err
			}
		}
	}

	return nil
}

// Serializes a FOR..IN expression
func (ys *YaraSerializer) serializeForInExpression(e *ForInExpression) error {
	if err := ys.writeString("for "); err != nil {
		return err
	}

	if err := ys.serializeForExpression(e.ForExpression); err != nil {
		return err
	}

	if err := ys.writeString(" " + e.GetIdentifier()); err != nil {
		return err
	}

	if err := ys.writeString(" in "); err != nil {
		return err
	}

	if err := ys.serializeIntegerSet(e.IntegerSet); err != nil {
		return err
	}

	if err := ys.writeString(" : ("); err != nil {
		return err
	}

	if err := ys.serializeExpression(e.Expression); err != nil {
		return err
	}

	return ys.writeString(")")
}

// Serializes a ForExpression.
func (ys *YaraSerializer) serializeForExpression(e *ForExpression) error {
	switch val := e.GetFor().(type) {
	case *ForExpression_Expression:
		return ys.serializeExpression(e.GetExpression())
	case *ForExpression_Keyword:
		return ys.serializeKeyword(e.GetKeyword())
	default:
		return fmt.Errorf(`Unsupported ForExpression value type "%s"`, val)
	}
}

// Serializes an IntegerSet.
func (ys *YaraSerializer) serializeIntegerSet(e *IntegerSet) error {
	switch val := e.GetSet().(type) {
	case *IntegerSet_IntegerEnumeration:
		return ys.serializeIntegerEnumeration(e.GetIntegerEnumeration())
	case *IntegerSet_Range:
		return ys.serializeRange(e.GetRange())
	default:
		return fmt.Errorf(`Unsupported IntegerSet value type "%s"`, val)
	}
}

// Serializes an IntegerEnumeration.
func (ys *YaraSerializer) serializeIntegerEnumeration(e *IntegerEnumeration) error {
	if err := ys.writeString("("); err != nil {
		return err
	}

	if err := ys.serializeTerms(e.Values, ", ", math.MinInt8); err != nil {
		return err
	}

	return ys.writeString(")")
}

// Serializes a Range expression.
func (ys *YaraSerializer) serializeRange(e *Range) error {
	if err := ys.writeString("("); err != nil {
		return err
	}

	if err := ys.serializeExpression(e.Start); err != nil {
		return err
	}

	if err := ys.writeString(".."); err != nil {
		return err
	}

	if err := ys.serializeExpression(e.End); err != nil {
		return err
	}

	return ys.writeString(")")
}

// Serializes a for..of expression
func (ys *YaraSerializer) serializeForOfExpression(e *ForOfExpression) error {
	if e.GetExpression() != nil {
		if err := ys.writeString("for "); err != nil {
			return err
		}
	}

	if err := ys.serializeForExpression(e.ForExpression); err != nil {
		return err
	}

	if err := ys.writeString(" of "); err != nil {
		return err
	}

	if err := ys.serializeStringSet(e.StringSet); err != nil {
		return err
	}

	if e.GetExpression() != nil {
		if err := ys.writeString(" : ("); err != nil {
			return err
		}

		if err := ys.serializeExpression(e.Expression); err != nil {
			return err
		}

		if err := ys.writeString(")"); err != nil {
			return err
		}
	}

	return nil
}

// Serializes a StringSet.
func (ys *YaraSerializer) serializeStringSet(e *StringSet) error {
	switch val := e.GetSet().(type) {
	case *StringSet_Strings:
		return ys.serializeStringEnumeration(e.GetStrings())
	case *StringSet_Keyword:
		return ys.serializeKeyword(e.GetKeyword())
	default:
		return fmt.Errorf(`Unsupported StringSet value type "%s"`, val)
	}
}

// Serializes a StringEnumeration.
func (ys *YaraSerializer) serializeStringEnumeration(e *StringEnumeration) error {
	if err := ys.writeString("("); err != nil {
		return err
	}

	for i, item := range e.GetItems() {
		if err := ys.writeString(item.GetStringIdentifier()); err != nil {
			return err
		}
		if i < len(e.GetItems())-1 {
			if err := ys.writeString(", "); err != nil {
				return err
			}
		}
	}

	return ys.writeString(")")
}

// Serializes a Keyword.
func (ys *YaraSerializer) serializeKeyword(e Keyword) error {
	kw, ok := keywords[e]
	if !ok {
		return fmt.Errorf(`Unknown keyword "%v"`, e)
	}

	return ys.writeString(kw)
}

// Serializes a BinaryExpression.
func (ys *YaraSerializer) serializeBinaryExpression(e *BinaryExpression) error {
	if e.Left.getPrecedence() < e.getPrecedence() {
		if err := ys.writeString("("); err != nil {
			return err
		}
	}
	if err := ys.serializeExpression(e.Left); err != nil {
		return err
	}
	if e.Left.getPrecedence() < e.getPrecedence() {
		if err := ys.writeString(")"); err != nil {
			return err
		}
	}

	op, ok := operators[e.GetOperator()]
	if !ok {
		return fmt.Errorf(`Unknown operator "%v"`, e.GetOperator())
	}

	if err := ys.writeString(" " + op + " "); err != nil {
		return err
	}

	if e.Right.getPrecedence() < e.getPrecedence() {
		if err := ys.writeString("("); err != nil {
			return err
		}
	}
	if err := ys.serializeExpression(e.Right); err != nil {
		return err
	}
	if e.Right.getPrecedence() < e.getPrecedence() {
		if err := ys.writeString(")"); err != nil {
			return err
		}
	}

	return nil
}

// Serializes an Identifier.
func (ys *YaraSerializer) serializeIdentifier(i *Identifier) error {
	for i, item := range i.GetItems() {
		switch val := item.GetItem().(type) {
		case *Identifier_IdentifierItem_Identifier:
			if i > 0 {
				if err := ys.writeString("."); err != nil {
					return err
				}
			}
			if err := ys.writeString(item.GetIdentifier()); err != nil {
				return err
			}
		case *Identifier_IdentifierItem_Expression:
			if err := ys.writeString("["); err != nil {
				return err
			}
			if err := ys.serializeExpression(item.GetExpression()); err != nil {
				return err
			}

			if err := ys.writeString("]"); err != nil {
				return err
			}
		case *Identifier_IdentifierItem_Arguments:
			if err := ys.writeString("("); err != nil {
				return err
			}

			for i, arg := range item.GetArguments().Terms {
				if err := ys.serializeExpression(arg); err != nil {
					return err
				}
				if i < len(item.GetArguments().Terms)-1 {
					if err := ys.writeString(", "); err != nil {
						return err
					}
				}
			}

			if err := ys.writeString(")"); err != nil {
				return err
			}
		default:
			return fmt.Errorf(`Unsupported identifier type "%T"`, val)
		}
	}

	return nil
}

// Serializes a Regexp, appending the i and s modifiers if included.
func (ys *YaraSerializer) serializeRegexp(r *Regexp) error {
	if err := ys.writeString("/"); err != nil {
		return err
	}

	if err := ys.writeString(r.GetText()); err != nil {
		return err
	}

	if err := ys.writeString("/"); err != nil {
		return err
	}

	if r.Modifiers.GetI() {
		if err := ys.writeString("i"); err != nil {
			return err
		}
	}
	if r.Modifiers.GetS() {
		if err := ys.writeString("s"); err != nil {
			return err
		}
	}

	return nil
}

// Serializes a NOT expression.
func (ys *YaraSerializer) serializeNotExpression(e *Expression) error {
	if err := ys.writeString("not "); err != nil {
		return err
	}

	if e.getPrecedence() < precedenceNotExpression {
		if err := ys.writeString("("); err != nil {
			return err
		}
	}

	if err := ys.serializeExpression(e); err != nil {
		return err
	}

	if e.getPrecedence() < precedenceNotExpression {
		if err := ys.writeString(")"); err != nil {
			return err
		}
	}

	return nil
}

// Serializes an IntegerFunction.
func (ys *YaraSerializer) serializeIntegerFunction(e *IntegerFunction) error {
	if err := ys.writeString(e.GetFunction()); err != nil {
		return err
	}

	if err := ys.writeString("("); err != nil {
		return err
	}

	if err := ys.serializeExpression(e.GetExpression()); err != nil {
		return err
	}

	return ys.writeString(")")
}

// Serializes a StringOffset.
func (ys *YaraSerializer) serializeStringOffset(e *StringOffset) error {
	if err := ys.writeString(e.GetStringIdentifier()); err != nil {
		return err
	}

	if e.GetIndex() != nil {
		if err := ys.writeString("["); err != nil {
			return err
		}
		if err := ys.serializeExpression(e.GetIndex()); err != nil {
			return err
		}
		if err := ys.writeString("]"); err != nil {
			return err
		}
	}

	return nil
}

// Serializes a StringLength.
func (ys *YaraSerializer) serializeStringLength(e *StringLength) error {
	if err := ys.writeString(e.GetStringIdentifier()); err != nil {
		return err
	}

	if e.GetIndex() != nil {
		if err := ys.writeString("["); err != nil {
			return err
		}
		if err := ys.serializeExpression(e.GetIndex()); err != nil {
			return err
		}
		if err := ys.writeString("]"); err != nil {
			return err
		}
	}

	return nil
}

// Returns the precedence of a BinaryExpression.
func (e *BinaryExpression) getPrecedence() int8 {
	prec, ok := binaryOperatorsPrecedence[e.GetOperator()]
	if !ok {
		return math.MaxInt8
	}

	return prec
}

func (ys *YaraSerializer) indent(level int) error {
	return ys.writeString(strings.Repeat(ys.Indent, level))
}

func (ys *YaraSerializer) writeString(str string) error {
	_, err := ys.w.Write([]byte(str))
	return err
}
