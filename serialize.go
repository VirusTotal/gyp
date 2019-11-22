// Functions and methods for serializing a RuleSet proto to YARA rules as strings.

package gyp

import (
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/VirusTotal/gyp/ast"
)

// YaraSerializer converts a RuleSet from proto to YARA ruleset.
// Contains configuration options.
type YaraSerializer struct {
	// Indentation string.
	indent string

	// Serialization output writer.
	w io.Writer
}

// NewSerializer returns a YaraSerializer that writes the serialization
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
func (ys *YaraSerializer) Serialize(rs *ast.RuleSet) error {
	return ys.serializeRuleSet(rs)
}

var keywords = map[ast.Keyword]string{
	ast.Keyword_ENTRYPOINT: "entrypoint",
	ast.Keyword_FILESIZE:   "filesize",
}

var forKeywords = map[ast.ForKeyword]string{
	ast.ForKeyword_ALL: "all",
	ast.ForKeyword_ANY: "any",
}

var stringSetKeywords = map[ast.StringSetKeyword]string{
	ast.StringSetKeyword_THEM: "them",
}

var operators = map[ast.BinaryExpression_Operator]string{
	ast.BinaryExpression_MATCHES:     "matches",
	ast.BinaryExpression_CONTAINS:    "contains",
	ast.BinaryExpression_AT:          "at",
	ast.BinaryExpression_IN:          "in",
	ast.BinaryExpression_BITWISE_OR:  "|",
	ast.BinaryExpression_XOR:         "^",
	ast.BinaryExpression_BITWISE_AND: "&",
	ast.BinaryExpression_EQ:          "==",
	ast.BinaryExpression_NEQ:         "!=",
	ast.BinaryExpression_LT:          "<",
	ast.BinaryExpression_LE:          "<=",
	ast.BinaryExpression_GT:          ">",
	ast.BinaryExpression_GE:          ">=",
	ast.BinaryExpression_SHIFT_LEFT:  "<<",
	ast.BinaryExpression_SHIFT_RIGHT: ">>",
	ast.BinaryExpression_PLUS:        "+",
	ast.BinaryExpression_MINUS:       "-",
	ast.BinaryExpression_TIMES:       "*",
	ast.BinaryExpression_DIV:         "\\",
	ast.BinaryExpression_MOD:         "%",
}

const precedenceOrExpression int8 = 1
const precedenceAndExpression int8 = 2

// Operators AT, IN, MATCHES and CONTAINS do not have a specified precedence.
// In those cases, the maximum precedence value should be assumed to prevent
// adding unnecessary parenthesis.
var binaryOperatorsPrecedence = map[ast.BinaryExpression_Operator]int8{
	ast.BinaryExpression_BITWISE_OR:  3,
	ast.BinaryExpression_XOR:         4,
	ast.BinaryExpression_BITWISE_AND: 5,
	ast.BinaryExpression_EQ:          6,
	ast.BinaryExpression_NEQ:         6,
	ast.BinaryExpression_LT:          7,
	ast.BinaryExpression_LE:          7,
	ast.BinaryExpression_GT:          7,
	ast.BinaryExpression_GE:          7,
	ast.BinaryExpression_SHIFT_LEFT:  8,
	ast.BinaryExpression_SHIFT_RIGHT: 8,
	ast.BinaryExpression_PLUS:        9,
	ast.BinaryExpression_MINUS:       9,
	ast.BinaryExpression_TIMES:       10,
	ast.BinaryExpression_DIV:         10,
	ast.BinaryExpression_MOD:         10,
}

const precedenceNotExpression int8 = 15
const precedenceUnaryExpression int8 = 15

func getExpressionPrecedence(e *ast.Expression) int8 {
	switch e.GetExpression().(type) {
	case *ast.Expression_OrExpression:
		return precedenceOrExpression
	case *ast.Expression_AndExpression:
		return precedenceAndExpression
	case *ast.Expression_BinaryExpression:
		return getBinaryExpressionPrecedence(e.GetBinaryExpression())
	case *ast.Expression_NotExpression:
		return precedenceNotExpression
	case *ast.Expression_UnaryExpression:
		return precedenceUnaryExpression
	default:
		// Expression with no precedence defined. Return maximum value.
		return math.MaxInt8
	}
}

func getBinaryExpressionPrecedence(e *ast.BinaryExpression) int8 {
	prec, ok := binaryOperatorsPrecedence[e.GetOperator()]
	if !ok {
		return math.MaxInt8
	}

	return prec
}

// Serializes a complete YARA ruleset.
func (ys *YaraSerializer) serializeRuleSet(rs *ast.RuleSet) error {
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
func (ys *YaraSerializer) serializeRule(r *ast.Rule) error {
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

	if err := ys.SerializeExpression(r.Condition); err != nil {
		return err
	}

	if err := ys.writeString("\n}\n\n"); err != nil {
		return err
	}

	return nil
}

// Serializes the "meta:" section in a YARA rule.
func (ys *YaraSerializer) serializeMetas(ms []*ast.Meta) error {
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
func (ys *YaraSerializer) serializeMeta(m *ast.Meta) error {
	switch val := m.GetValue().(type) {
	case *ast.Meta_Text:
		return ys.writeString(fmt.Sprintf(`%s = "%s"`, m.GetKey(), m.GetText()))
	case *ast.Meta_Number:
		return ys.writeString(fmt.Sprintf(`%s = %v`, m.GetKey(), m.GetNumber()))
	case *ast.Meta_Boolean:
		return ys.writeString(fmt.Sprintf(`%s = %v`, m.GetKey(), m.GetBoolean()))
	default:
		return fmt.Errorf(`Unsupported Meta value type "%T"`, val)
	}
}

// Serializes the "strings:" section in a YARA rule.
func (ys *YaraSerializer) serializeStrings(strs []*ast.String) error {
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

func (ys *YaraSerializer) serializeString(str *ast.String) error {
	if err := ys.writeString(fmt.Sprintf("%s = ", str.GetId())); err != nil {
		return err
	}

	return ys.SerializeStringValue(str)
}

// Serializes the value of a string in a YARA rule.
func (ys *YaraSerializer) SerializeStringValue(str *ast.String) error {
	switch val := str.GetValue().(type) {
	case *ast.String_Text:
		return ys.serializeTextString(str.GetText())
	case *ast.String_Hex:
		return ys.serializeHexString(str.GetHex())
	case *ast.String_Regexp:
		if err := ys.serializeRegexp(str.GetRegexp()); err != nil {
			return err
		}
		return ys.serializeStringModifiers(str.GetRegexp().Modifiers)
	default:
		return fmt.Errorf(`Unsupported String value type "%T"`, val)
	}

	return nil
}

func (ys *YaraSerializer) serializeTextString(t *ast.TextString) error {
	if err := ys.writeString(fmt.Sprintf("%q", t.GetText())); err != nil {
		return err
	}

	return ys.serializeStringModifiers(t.Modifiers)
}

// Serialize for StringModifiers creates a space-sparated list of
// string modifiers, excluding the i and s which are appended to /regex/
func (ys *YaraSerializer) serializeStringModifiers(m *ast.StringModifiers) error {
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
	if m.GetPrivate() {
		modifiers = append(modifiers, "private")
	}
	if m.GetXor() {
		modifier := "xor"
		min := m.GetXorMin()
		max := m.GetXorMax()
		if min != 0 || max != 255 {
			if min == max {
				modifier = fmt.Sprintf("xor(%d)", min)
			} else {
				modifier = fmt.Sprintf("xor(%d-%d)", min, max)
			}
		}
		modifiers = append(modifiers, modifier)
	}

	if len(modifiers) == 0 {
		return nil
	}

	if err := ys.writeString(" "); err != nil {
		return err
	}

	return ys.writeString(strings.Join(modifiers, " "))
}

func (ys *YaraSerializer) serializeHexString(h *ast.HexTokens) error {
	if err := ys.writeString("{ "); err != nil {
		return err
	}

	if err := ys.serializeHexTokens(h); err != nil {
		return err
	}

	return ys.writeString("}")
}

func (ys *YaraSerializer) serializeHexTokens(ts *ast.HexTokens) error {
	for _, t := range ts.Token {
		if err := ys.serializeHexToken(t); err != nil {
			return err
		}
	}

	return nil
}

func (ys *YaraSerializer) serializeHexToken(t *ast.HexToken) error {
	switch val := t.GetValue().(type) {
	case *ast.HexToken_Sequence:
		return ys.serializeBytesSequence(t.GetSequence())
	case *ast.HexToken_Jump:
		return ys.serializeJump(t.GetJump())
	case *ast.HexToken_Alternative:
		return ys.serializeHexAlternative(t.GetAlternative())
	default:
		return fmt.Errorf(`Unsupported HexToken type: "%T"`, val)
	}
}

func (ys *YaraSerializer) serializeBytesSequence(b *ast.BytesSequence) error {
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
			return fmt.Errorf(`Unsupported byte mask: "%x"`, mask)
		}
	}

	return nil
}

func (ys *YaraSerializer) serializeJump(jump *ast.Jump) error {
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

func (ys *YaraSerializer) serializeHexAlternative(alt *ast.HexAlternative) error {
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

// SerializeExpression serializes an Expression in a YARA rule condition.
func (ys *YaraSerializer) SerializeExpression(e *ast.Expression) error {
	switch val := e.GetExpression().(type) {
	case *ast.Expression_BoolValue:
		return ys.writeString(fmt.Sprintf("%v", e.GetBoolValue()))
	case *ast.Expression_OrExpression:
		return ys.serializeOrExpression(e.GetOrExpression())
	case *ast.Expression_AndExpression:
		return ys.serializeAndExpression(e.GetAndExpression())
	case *ast.Expression_StringIdentifier:
		return ys.writeString(e.GetStringIdentifier())
	case *ast.Expression_ForInExpression:
		return ys.serializeForInExpression(e.GetForInExpression())
	case *ast.Expression_ForOfExpression:
		return ys.serializeForOfExpression(e.GetForOfExpression())
	case *ast.Expression_BinaryExpression:
		return ys.serializeBinaryExpression(e.GetBinaryExpression())
	case *ast.Expression_Text:
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
	case *ast.Expression_NumberValue:
		return ys.writeString(fmt.Sprintf("%d", e.GetNumberValue()))
	case *ast.Expression_DoubleValue:
		return ys.writeString(fmt.Sprintf("%f", e.GetDoubleValue()))
	case *ast.Expression_Range:
		return ys.serializeRange(e.GetRange())
	case *ast.Expression_Keyword:
		return ys.serializeKeyword(e.GetKeyword())
	case *ast.Expression_Identifier:
		return ys.serializeIdentifier(e.GetIdentifier())
	case *ast.Expression_Regexp:
		return ys.serializeRegexp(e.GetRegexp())
	case *ast.Expression_NotExpression:
		return ys.serializeNotExpression(e.GetNotExpression())
	case *ast.Expression_IntegerFunction:
		return ys.serializeIntegerFunction(e.GetIntegerFunction())
	case *ast.Expression_StringOffset:
		return ys.serializeStringOffset(e.GetStringOffset())
	case *ast.Expression_StringLength:
		return ys.serializeStringLength(e.GetStringLength())
	case *ast.Expression_StringCount:
		return ys.writeString(e.GetStringCount())
	default:
		return fmt.Errorf(`Unsupported Expression type "%T"`, val)
	}
}

// Serializes an OR expression.
func (ys *YaraSerializer) serializeOrExpression(es *ast.Expressions) error {
	return ys.serializeTerms(es.Terms, " or ", precedenceOrExpression)
}

// Serializes an AND expression.
func (ys *YaraSerializer) serializeAndExpression(es *ast.Expressions) error {
	return ys.serializeTerms(es.Terms, " and ", precedenceAndExpression)
}

func (ys *YaraSerializer) serializeTerms(terms []*ast.Expression, joinStr string, precedence int8) error {
	for i, term := range terms {
		addParens := getExpressionPrecedence(term) < precedenceAndExpression
		if addParens {
			if err := ys.writeString("("); err != nil {
				return err
			}
		}

		if err := ys.SerializeExpression(term); err != nil {
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
func (ys *YaraSerializer) serializeForInExpression(e *ast.ForInExpression) error {
	if err := ys.writeString("for "); err != nil {
		return err
	}

	if err := ys.serializeForExpression(e.ForExpression); err != nil {
		return err
	}

	if err := ys.writeString(" " + strings.Join(e.GetIdentifiers(), ",")); err != nil {
		return err
	}

	if err := ys.writeString(" in "); err != nil {
		return err
	}

	if err := ys.serializeIterator(e.Iterator); err != nil {
		return err
	}

	if err := ys.writeString(" : ("); err != nil {
		return err
	}

	if err := ys.SerializeExpression(e.Expression); err != nil {
		return err
	}

	return ys.writeString(")")
}

// Serializes a ForExpression.
func (ys *YaraSerializer) serializeForExpression(e *ast.ForExpression) error {
	switch val := e.GetFor().(type) {
	case *ast.ForExpression_Expression:
		return ys.SerializeExpression(e.GetExpression())
	case *ast.ForExpression_Keyword:
		return ys.serializeForKeyword(e.GetKeyword())
	default:
		return fmt.Errorf(`Unsupported ForExpression value type "%s"`, val)
	}
}

func (ys *YaraSerializer) serializeIterator(e *ast.Iterator) error {
	switch val := e.GetIterator().(type) {
	case *ast.Iterator_IntegerSet:
		return ys.serializeIntegerSet(e.GetIntegerSet())
	case *ast.Iterator_Identifier:
		return ys.serializeIdentifier(e.GetIdentifier())
	default:
		return fmt.Errorf(`Unsupported Iterator value type "%s"`, val)
	}
}

// Serializes an IntegerSet.
func (ys *YaraSerializer) serializeIntegerSet(e *ast.IntegerSet) error {
	switch val := e.GetSet().(type) {
	case *ast.IntegerSet_IntegerEnumeration:
		return ys.serializeIntegerEnumeration(e.GetIntegerEnumeration())
	case *ast.IntegerSet_Range:
		return ys.serializeRange(e.GetRange())
	default:
		return fmt.Errorf(`Unsupported IntegerSet value type "%s"`, val)
	}
}

// Serializes an IntegerEnumeration.
func (ys *YaraSerializer) serializeIntegerEnumeration(e *ast.IntegerEnumeration) error {
	if err := ys.writeString("("); err != nil {
		return err
	}

	if err := ys.serializeTerms(e.Values, ", ", math.MinInt8); err != nil {
		return err
	}

	return ys.writeString(")")
}

// Serializes a Range expression.
func (ys *YaraSerializer) serializeRange(e *ast.Range) error {
	if err := ys.writeString("("); err != nil {
		return err
	}

	if err := ys.SerializeExpression(e.Start); err != nil {
		return err
	}

	if err := ys.writeString(".."); err != nil {
		return err
	}

	if err := ys.SerializeExpression(e.End); err != nil {
		return err
	}

	return ys.writeString(")")
}

// Serializes a for..of expression
func (ys *YaraSerializer) serializeForOfExpression(e *ast.ForOfExpression) error {
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

		if err := ys.SerializeExpression(e.Expression); err != nil {
			return err
		}

		if err := ys.writeString(")"); err != nil {
			return err
		}
	}

	return nil
}

// Serializes a StringSet.
func (ys *YaraSerializer) serializeStringSet(e *ast.StringSet) error {
	switch val := e.GetSet().(type) {
	case *ast.StringSet_Strings:
		return ys.serializeStringEnumeration(e.GetStrings())
	case *ast.StringSet_Keyword:
		return ys.serializeStringSetKeyword(e.GetKeyword())
	default:
		return fmt.Errorf(`Unsupported StringSet value type "%s"`, val)
	}
}

// Serializes a StringEnumeration.
func (ys *YaraSerializer) serializeStringEnumeration(e *ast.StringEnumeration) error {
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
func (ys *YaraSerializer) serializeKeyword(e ast.Keyword) error {
	kw, ok := keywords[e]
	if !ok {
		return fmt.Errorf(`Unknown keyword "%v"`, e)
	}

	return ys.writeString(kw)
}

// Serializes a ForKeyword.
func (ys *YaraSerializer) serializeForKeyword(e ast.ForKeyword) error {
	kw, ok := forKeywords[e]
	if !ok {
		return fmt.Errorf(`Unknown keyword "%v"`, e)
	}

	return ys.writeString(kw)
}

// Serializes a StringSetKeyword.
func (ys *YaraSerializer) serializeStringSetKeyword(e ast.StringSetKeyword) error {
	kw, ok := stringSetKeywords[e]
	if !ok {
		return fmt.Errorf(`Unknown keyword "%v"`, e)
	}

	return ys.writeString(kw)
}

// Serializes a BinaryExpression.
func (ys *YaraSerializer) serializeBinaryExpression(e *ast.BinaryExpression) error {
	if getExpressionPrecedence(e.Left) < getBinaryExpressionPrecedence(e) {
		if err := ys.writeString("("); err != nil {
			return err
		}
	}
	if err := ys.SerializeExpression(e.Left); err != nil {
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
	if err := ys.SerializeExpression(e.Right); err != nil {
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
func (ys *YaraSerializer) serializeIdentifier(i *ast.Identifier) error {
	for i, item := range i.GetItems() {
		switch val := item.GetItem().(type) {
		case *ast.Identifier_IdentifierItem_Identifier:
			if i > 0 {
				if err := ys.writeString("."); err != nil {
					return err
				}
			}
			if err := ys.writeString(item.GetIdentifier()); err != nil {
				return err
			}
		case *ast.Identifier_IdentifierItem_Index:
			if err := ys.writeString("["); err != nil {
				return err
			}
			if err := ys.SerializeExpression(item.GetIndex()); err != nil {
				return err
			}

			if err := ys.writeString("]"); err != nil {
				return err
			}
		case *ast.Identifier_IdentifierItem_Arguments:
			if err := ys.writeString("("); err != nil {
				return err
			}

			for i, arg := range item.GetArguments().Terms {
				if err := ys.SerializeExpression(arg); err != nil {
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
func (ys *YaraSerializer) serializeRegexp(r *ast.Regexp) error {
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
func (ys *YaraSerializer) serializeNotExpression(e *ast.Expression) error {
	if err := ys.writeString("not "); err != nil {
		return err
	}

	if getExpressionPrecedence(e) < precedenceNotExpression {
		if err := ys.writeString("("); err != nil {
			return err
		}
	}

	if err := ys.SerializeExpression(e); err != nil {
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
func (ys *YaraSerializer) serializeIntegerFunction(e *ast.IntegerFunction) error {
	if err := ys.writeString(e.GetFunction()); err != nil {
		return err
	}

	if err := ys.writeString("("); err != nil {
		return err
	}

	if err := ys.SerializeExpression(e.GetArgument()); err != nil {
		return err
	}

	return ys.writeString(")")
}

// Serializes a StringOffset.
func (ys *YaraSerializer) serializeStringOffset(e *ast.StringOffset) error {
	if err := ys.writeString(e.GetStringIdentifier()); err != nil {
		return err
	}

	if e.GetIndex() != nil {
		if err := ys.writeString("["); err != nil {
			return err
		}
		if err := ys.SerializeExpression(e.GetIndex()); err != nil {
			return err
		}
		if err := ys.writeString("]"); err != nil {
			return err
		}
	}

	return nil
}

// Serializes a StringLength.
func (ys *YaraSerializer) serializeStringLength(e *ast.StringLength) error {
	if err := ys.writeString(e.GetStringIdentifier()); err != nil {
		return err
	}

	if e.GetIndex() != nil {
		if err := ys.writeString("["); err != nil {
			return err
		}
		if err := ys.SerializeExpression(e.GetIndex()); err != nil {
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
