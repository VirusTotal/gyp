// Functions and methods for serializing a RuleSet proto to YARA rules as strings.

package gyp

import (
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/VirusTotal/gyp/data"
)

// YaraSerializer converts a RuleSet from proto to YARA ruleset.
// Contains configuration options.
type YaraSerializer struct {
	// Indentation string.
	indent string

	// Serialization output writer.
	w io.Writer
}

// NewSerialize returns a YaraSerializer that writes the serialization
// output to w.
func NewSerializer(w io.Writer) *YaraSerializer {
	return &YaraSerializer{indent: "  ", w: w}
}

// SetIndent sets the indentation string used for each indentation level.
// Default value: 2 whitespaces.
func (ys *YaraSerializer) SetIndent(indent string) {
	ys.indent = indent
}

// Serialize converts the provided RuleSet proto to a YARA ruleset.
func (ys *YaraSerializer) Serialize(rs data.RuleSet) error {
	return ys.serializeRuleSet(&rs)
}

var keywords = map[data.Keyword]string{
	data.Keyword_ENTRYPOINT: "entrypoint",
	data.Keyword_FILESIZE:   "filesize",
}

var forKeywords = map[data.ForKeyword]string{
	data.ForKeyword_ALL: "all",
	data.ForKeyword_ANY: "any",
}

var stringSetKeywords = map[data.StringSetKeyword]string{
	data.StringSetKeyword_THEM: "them",
}

var operators = map[data.BinaryExpression_Operator]string{
	data.BinaryExpression_MATCHES:     "matches",
	data.BinaryExpression_CONTAINS:    "contains",
	data.BinaryExpression_AT:          "at",
	data.BinaryExpression_IN:          "in",
	data.BinaryExpression_BITWISE_OR:  "|",
	data.BinaryExpression_XOR:         "^",
	data.BinaryExpression_BITWISE_AND: "&",
	data.BinaryExpression_EQ:          "==",
	data.BinaryExpression_NEQ:         "!=",
	data.BinaryExpression_LT:          "<",
	data.BinaryExpression_LE:          "<=",
	data.BinaryExpression_GT:          ">",
	data.BinaryExpression_GE:          ">=",
	data.BinaryExpression_SHIFT_LEFT:  "<<",
	data.BinaryExpression_SHIFT_RIGHT: ">>",
	data.BinaryExpression_PLUS:        "+",
	data.BinaryExpression_MINUS:       "-",
	data.BinaryExpression_TIMES:       "*",
	data.BinaryExpression_DIV:         "\\",
	data.BinaryExpression_MOD:         "%",
}

const precedenceOrExpression int8 = 1
const precedenceAndExpression int8 = 2

// Operators AT, IN, MATCHES and CONTAINS do not have a specified precedence.
// In those cases, the maximum precedence value should be assumed to prevent
// adding unnecessary parenthesis.
var binaryOperatorsPrecedence = map[data.BinaryExpression_Operator]int8{
	data.BinaryExpression_BITWISE_OR:  3,
	data.BinaryExpression_XOR:         4,
	data.BinaryExpression_BITWISE_AND: 5,
	data.BinaryExpression_EQ:          6,
	data.BinaryExpression_NEQ:         6,
	data.BinaryExpression_LT:          7,
	data.BinaryExpression_LE:          7,
	data.BinaryExpression_GT:          7,
	data.BinaryExpression_GE:          7,
	data.BinaryExpression_SHIFT_LEFT:  8,
	data.BinaryExpression_SHIFT_RIGHT: 8,
	data.BinaryExpression_PLUS:        9,
	data.BinaryExpression_MINUS:       9,
	data.BinaryExpression_TIMES:       10,
	data.BinaryExpression_DIV:         10,
	data.BinaryExpression_MOD:         10,
}

const precedenceNotExpression int8 = 15
const precedenceUnaryExpression int8 = 15

func getExpressionPrecedence(e *data.Expression) int8 {
	switch e.GetExpression().(type) {
	case *data.Expression_OrExpression:
		return precedenceOrExpression
	case *data.Expression_AndExpression:
		return precedenceAndExpression
	case *data.Expression_BinaryExpression:
		return getBinaryExpressionPrecedence(e.GetBinaryExpression())
	case *data.Expression_NotExpression:
		return precedenceNotExpression
	case *data.Expression_UnaryExpression:
		return precedenceUnaryExpression
	default:
		// Expression with no precedence defined. Return maximum value.
		return math.MaxInt8
	}
}

func getBinaryExpressionPrecedence(e *data.BinaryExpression) int8 {
	prec, ok := binaryOperatorsPrecedence[e.GetOperator()]
	if !ok {
		return math.MaxInt8
	}

	return prec
}

// Serializes a complete YARA ruleset.
func (ys *YaraSerializer) serializeRuleSet(rs *data.RuleSet) error {
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
func (ys *YaraSerializer) serializeRule(r *data.Rule) error {
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

	if err := ys.writeIndent(1); err != nil {
		return err
	}

	if err := ys.writeString("condition:\n"); err != nil {
		return err
	}

	if err := ys.writeIndent(2); err != nil {
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
func (ys *YaraSerializer) serializeMetas(ms []*data.Meta) error {
	if ms == nil || len(ms) == 0 {
		return nil
	}

	if err := ys.writeIndent(1); err != nil {
		return err
	}

	if err := ys.writeString("meta:\n"); err != nil {
		return err
	}

	for _, m := range ms {
		if err := ys.writeIndent(2); err != nil {
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
func (ys *YaraSerializer) serializeMeta(m *data.Meta) error {
	switch val := m.GetValue().(type) {
	case *data.Meta_Text:
		return ys.writeString(fmt.Sprintf(`%s = "%s"`, m.GetKey(), m.GetText()))
	case *data.Meta_Number:
		return ys.writeString(fmt.Sprintf(`%s = %v`, m.GetKey(), m.GetNumber()))
	case *data.Meta_Boolean:
		return ys.writeString(fmt.Sprintf(`%s = %v`, m.GetKey(), m.GetBoolean()))
	default:
		return fmt.Errorf(`Unsupported Meta value type "%T"`, val)
	}
}

// Serializes the "strings:" section in a YARA rule.
func (ys *YaraSerializer) serializeStrings(strs []*data.String) error {
	if strs == nil || len(strs) == 0 {
		return nil
	}

	if err := ys.writeIndent(1); err != nil {
		return err
	}

	if err := ys.writeString("strings:\n"); err != nil {
		return err
	}

	for _, str := range strs {
		if err := ys.writeIndent(2); err != nil {
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
func (ys *YaraSerializer) serializeString(str *data.String) error {
	if err := ys.writeString(fmt.Sprintf("%s = ", str.GetId())); err != nil {
		return err
	}

	switch val := str.GetValue().(type) {
	case *data.String_Text:
		return ys.serializeTextString(str.GetText())
	case *data.String_Hex:
		return ys.serializeHexString(str.GetHex())
	case *data.String_Regexp:
		if err := ys.serializeRegexp(str.GetRegexp()); err != nil {
			return err
		}
		return ys.serializeStringModifiers(str.GetRegexp().Modifiers)
	default:
		return fmt.Errorf(`Unsupported String value type "%T"`, val)
	}

	return nil
}

func (ys *YaraSerializer) serializeTextString(t *data.TextString) error {
	if err := ys.writeString(fmt.Sprintf(`"%s"`, t.GetText())); err != nil {
		return err
	}

	return ys.serializeStringModifiers(t.Modifiers)
}

// Serialize for StringModifiers creates a space-sparated list of
// string modifiers, excluding the i and s which are appended to /regex/
func (ys *YaraSerializer) serializeStringModifiers(m *data.StringModifiers) error {
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

func (ys *YaraSerializer) serializeHexString(h *data.HexTokens) error {
	if err := ys.writeString("{ "); err != nil {
		return err
	}

	if err := ys.serializeHexTokens(h); err != nil {
		return err
	}

	return ys.writeString("}")
}

func (ys *YaraSerializer) serializeHexTokens(ts *data.HexTokens) error {
	for _, t := range ts.Token {
		if err := ys.serializeHexToken(t); err != nil {
			return err
		}
	}

	return nil
}

func (ys *YaraSerializer) serializeHexToken(t *data.HexToken) error {
	switch val := t.GetValue().(type) {
	case *data.HexToken_Sequence:
		return ys.serializeBytesSequence(t.GetSequence())
	case *data.HexToken_Jump:
		return ys.serializeJump(t.GetJump())
	case *data.HexToken_Alternative:
		return ys.serializeHexAlternative(t.GetAlternative())
	default:
		return fmt.Errorf(`Unsupported HexToken type: "%T"`, val)
	}
}

func (ys *YaraSerializer) serializeBytesSequence(b *data.BytesSequence) error {
	if len(b.Value) != len(b.Mask) {
		return fmt.Errorf(
			`Length of value and mask bytes must match in a BytesSequence. Found: %d, %d`,
			len(b.Value),
			len(b.Mask))
	}

	for i, val := range b.Value {
		switch mask := b.Mask[i]; mask {
		case 0:
			if err := ys.writeString("?? "); err != nil {
				return err
			}
		case 0x0F:
			valStr := fmt.Sprintf("%02X", val)
			if err := ys.writeString("?" + string(valStr[1]) + " "); err != nil {
				return err
			}
		case 0xF0:
			valStr := fmt.Sprintf("%02X", val)
			if err := ys.writeString(string(valStr[0]) + "? "); err != nil {
				return err
			}
		case 0xFF:
			if err := ys.writeString(fmt.Sprintf("%02X ", val)); err != nil {
				return err
			}
		default:
			return fmt.Errorf(`Unsupported byte mask: "%s"`, mask)
		}
	}

	return nil
}

func (ys *YaraSerializer) serializeJump(jump *data.Jump) error {
	if err := ys.writeString("["); err != nil {
		return err
	}

	if jump.Start != nil && jump.End != nil && jump.GetStart() == jump.GetEnd() {
		return ys.writeString(fmt.Sprintf("%d] ", jump.GetStart()))
	}

	if jump.Start != nil {
		if err := ys.writeString(fmt.Sprintf("%d", jump.GetStart())); err != nil {
			return err
		}
	}

	if err := ys.writeString("-"); err != nil {
		return err
	}

	if jump.End != nil {
		if err := ys.writeString(fmt.Sprintf("%d", jump.GetEnd())); err != nil {
			return err
		}
	}

	if err := ys.writeString("] "); err != nil {
		return err
	}

	return nil
}

func (ys *YaraSerializer) serializeHexAlternative(alt *data.HexAlternative) error {
	if err := ys.writeString("( "); err != nil {
		return err
	}

	for i, tokens := range alt.Tokens {
		ys.serializeHexTokens(tokens)
		if i < len(alt.Tokens)-1 {
			if err := ys.writeString("| "); err != nil {
				return err
			}
		}
	}

	if err := ys.writeString(") "); err != nil {
		return err
	}

	return nil
}

// Serializes an Expression in a YARA rule condition.
func (ys *YaraSerializer) serializeExpression(e *data.Expression) error {
	switch val := e.GetExpression().(type) {
	case *data.Expression_BoolValue:
		return ys.writeString(fmt.Sprintf("%v", e.GetBoolValue()))
	case *data.Expression_OrExpression:
		return ys.serializeOrExpression(e.GetOrExpression())
	case *data.Expression_AndExpression:
		return ys.serializeAndExpression(e.GetAndExpression())
	case *data.Expression_StringIdentifier:
		return ys.writeString(e.GetStringIdentifier())
	case *data.Expression_ForInExpression:
		return ys.serializeForInExpression(e.GetForInExpression())
	case *data.Expression_ForOfExpression:
		return ys.serializeForOfExpression(e.GetForOfExpression())
	case *data.Expression_BinaryExpression:
		return ys.serializeBinaryExpression(e.GetBinaryExpression())
	case *data.Expression_Text:
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
	case *data.Expression_NumberValue:
		return ys.writeString(fmt.Sprintf("%d", e.GetNumberValue()))
	case *data.Expression_DoubleValue:
		return ys.writeString(fmt.Sprintf("%f", e.GetDoubleValue()))
	case *data.Expression_Range:
		return ys.serializeRange(e.GetRange())
	case *data.Expression_Keyword:
		return ys.serializeKeyword(e.GetKeyword())
	case *data.Expression_Identifier:
		return ys.serializeIdentifier(e.GetIdentifier())
	case *data.Expression_Regexp:
		return ys.serializeRegexp(e.GetRegexp())
	case *data.Expression_NotExpression:
		return ys.serializeNotExpression(e.GetNotExpression())
	case *data.Expression_IntegerFunction:
		return ys.serializeIntegerFunction(e.GetIntegerFunction())
	case *data.Expression_StringOffset:
		return ys.serializeStringOffset(e.GetStringOffset())
	case *data.Expression_StringLength:
		return ys.serializeStringLength(e.GetStringLength())
	case *data.Expression_StringCount:
		return ys.writeString(e.GetStringCount())
	default:
		return fmt.Errorf(`Unsupported Expression type "%T"`, val)
	}
}

// Serializes an OR expression.
func (ys *YaraSerializer) serializeOrExpression(es *data.Expressions) error {
	return ys.serializeTerms(es.Terms, " or ", precedenceOrExpression)
}

// Serializes an AND expression.
func (ys *YaraSerializer) serializeAndExpression(es *data.Expressions) error {
	return ys.serializeTerms(es.Terms, " and ", precedenceAndExpression)
}

func (ys *YaraSerializer) serializeTerms(terms []*data.Expression, joinStr string, precedence int8) error {
	for i, term := range terms {
		addParens := getExpressionPrecedence(term) < precedenceAndExpression
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
func (ys *YaraSerializer) serializeForInExpression(e *data.ForInExpression) error {
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
func (ys *YaraSerializer) serializeForExpression(e *data.ForExpression) error {
	switch val := e.GetFor().(type) {
	case *data.ForExpression_Expression:
		return ys.serializeExpression(e.GetExpression())
	case *data.ForExpression_Keyword:
		return ys.serializeForKeyword(e.GetKeyword())
	default:
		return fmt.Errorf(`Unsupported ForExpression value type "%s"`, val)
	}
}

// Serializes an IntegerSet.
func (ys *YaraSerializer) serializeIntegerSet(e *data.IntegerSet) error {
	switch val := e.GetSet().(type) {
	case *data.IntegerSet_IntegerEnumeration:
		return ys.serializeIntegerEnumeration(e.GetIntegerEnumeration())
	case *data.IntegerSet_Range:
		return ys.serializeRange(e.GetRange())
	default:
		return fmt.Errorf(`Unsupported IntegerSet value type "%s"`, val)
	}
}

// Serializes an IntegerEnumeration.
func (ys *YaraSerializer) serializeIntegerEnumeration(e *data.IntegerEnumeration) error {
	if err := ys.writeString("("); err != nil {
		return err
	}

	if err := ys.serializeTerms(e.Values, ", ", math.MinInt8); err != nil {
		return err
	}

	return ys.writeString(")")
}

// Serializes a Range expression.
func (ys *YaraSerializer) serializeRange(e *data.Range) error {
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
func (ys *YaraSerializer) serializeForOfExpression(e *data.ForOfExpression) error {
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
func (ys *YaraSerializer) serializeStringSet(e *data.StringSet) error {
	switch val := e.GetSet().(type) {
	case *data.StringSet_Strings:
		return ys.serializeStringEnumeration(e.GetStrings())
	case *data.StringSet_Keyword:
		return ys.serializeStringSetKeyword(e.GetKeyword())
	default:
		return fmt.Errorf(`Unsupported StringSet value type "%s"`, val)
	}
}

// Serializes a StringEnumeration.
func (ys *YaraSerializer) serializeStringEnumeration(e *data.StringEnumeration) error {
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
func (ys *YaraSerializer) serializeKeyword(e data.Keyword) error {
	kw, ok := keywords[e]
	if !ok {
		return fmt.Errorf(`Unknown keyword "%v"`, e)
	}

	return ys.writeString(kw)
}

// Serializes a ForKeyword.
func (ys *YaraSerializer) serializeForKeyword(e data.ForKeyword) error {
	kw, ok := forKeywords[e]
	if !ok {
		return fmt.Errorf(`Unknown keyword "%v"`, e)
	}

	return ys.writeString(kw)
}

// Serializes a StringSetKeyword.
func (ys *YaraSerializer) serializeStringSetKeyword(e data.StringSetKeyword) error {
	kw, ok := stringSetKeywords[e]
	if !ok {
		return fmt.Errorf(`Unknown keyword "%v"`, e)
	}

	return ys.writeString(kw)
}

// Serializes a BinaryExpression.
func (ys *YaraSerializer) serializeBinaryExpression(e *data.BinaryExpression) error {
	if getExpressionPrecedence(e.Left) < getBinaryExpressionPrecedence(e) {
		if err := ys.writeString("("); err != nil {
			return err
		}
	}
	if err := ys.serializeExpression(e.Left); err != nil {
		return err
	}
	if getExpressionPrecedence(e.Left) < getBinaryExpressionPrecedence(e) {
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

	if getExpressionPrecedence(e.Right) < getBinaryExpressionPrecedence(e) {
		if err := ys.writeString("("); err != nil {
			return err
		}
	}
	if err := ys.serializeExpression(e.Right); err != nil {
		return err
	}
	if getExpressionPrecedence(e.Right) < getBinaryExpressionPrecedence(e) {
		if err := ys.writeString(")"); err != nil {
			return err
		}
	}

	return nil
}

// Serializes an Identifier.
func (ys *YaraSerializer) serializeIdentifier(i *data.Identifier) error {
	for i, item := range i.GetItems() {
		switch val := item.GetItem().(type) {
		case *data.Identifier_IdentifierItem_Identifier:
			if i > 0 {
				if err := ys.writeString("."); err != nil {
					return err
				}
			}
			if err := ys.writeString(item.GetIdentifier()); err != nil {
				return err
			}
		case *data.Identifier_IdentifierItem_Expression:
			if err := ys.writeString("["); err != nil {
				return err
			}
			if err := ys.serializeExpression(item.GetExpression()); err != nil {
				return err
			}

			if err := ys.writeString("]"); err != nil {
				return err
			}
		case *data.Identifier_IdentifierItem_Arguments:
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
func (ys *YaraSerializer) serializeRegexp(r *data.Regexp) error {
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
func (ys *YaraSerializer) serializeNotExpression(e *data.Expression) error {
	if err := ys.writeString("not "); err != nil {
		return err
	}

	if getExpressionPrecedence(e) < precedenceNotExpression {
		if err := ys.writeString("("); err != nil {
			return err
		}
	}

	if err := ys.serializeExpression(e); err != nil {
		return err
	}

	if getExpressionPrecedence(e) < precedenceNotExpression {
		if err := ys.writeString(")"); err != nil {
			return err
		}
	}

	return nil
}

// Serializes an IntegerFunction.
func (ys *YaraSerializer) serializeIntegerFunction(e *data.IntegerFunction) error {
	if err := ys.writeString(e.GetFunction()); err != nil {
		return err
	}

	if err := ys.writeString("("); err != nil {
		return err
	}

	if err := ys.serializeExpression(e.GetOffsetOrVaddress()); err != nil {
		return err
	}

	return ys.writeString(")")
}

// Serializes a StringOffset.
func (ys *YaraSerializer) serializeStringOffset(e *data.StringOffset) error {
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
func (ys *YaraSerializer) serializeStringLength(e *data.StringLength) error {
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

func (ys *YaraSerializer) writeIndent(level int) error {
	return ys.writeString(strings.Repeat(ys.indent, level))
}

func (ys *YaraSerializer) writeString(str string) error {
	_, err := ys.w.Write([]byte(str))
	return err
}
