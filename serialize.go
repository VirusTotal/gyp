// Functions and methods for serializing a RuleSet proto to YARA rules as strings.

package gyp

import (
	"fmt"
	"github.com/VirusTotal/gyp/ast"
	"io"
	"math"
	"strings"

	"github.com/VirusTotal/gyp/pb"
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
func (ys *YaraSerializer) Serialize(rs *pb.RuleSet) error {
	return ys.serializeRuleSet(rs)
}

var keywords = map[pb.Keyword]string{
	pb.Keyword_ENTRYPOINT: "entrypoint",
	pb.Keyword_FILESIZE:   "filesize",
}

var forKeywords = map[pb.ForKeyword]string{
	pb.ForKeyword_NONE: "none",
	pb.ForKeyword_ALL: "all",
	pb.ForKeyword_ANY: "any",
}

var stringSetKeywords = map[pb.StringSetKeyword]string{
	pb.StringSetKeyword_THEM: "them",
}

var operators = map[pb.BinaryExpression_Operator]string{
	pb.BinaryExpression_MATCHES:     "matches",
	pb.BinaryExpression_CONTAINS:    "contains",
	pb.BinaryExpression_AT:          "at",
	pb.BinaryExpression_IN:          "in",
	pb.BinaryExpression_BITWISE_OR:  "|",
	pb.BinaryExpression_XOR:         "^",
	pb.BinaryExpression_BITWISE_AND: "&",
	pb.BinaryExpression_EQ:          "==",
	pb.BinaryExpression_NEQ:         "!=",
	pb.BinaryExpression_LT:          "<",
	pb.BinaryExpression_LE:          "<=",
	pb.BinaryExpression_GT:          ">",
	pb.BinaryExpression_GE:          ">=",
	pb.BinaryExpression_SHIFT_LEFT:  "<<",
	pb.BinaryExpression_SHIFT_RIGHT: ">>",
	pb.BinaryExpression_PLUS:        "+",
	pb.BinaryExpression_MINUS:       "-",
	pb.BinaryExpression_TIMES:       "*",
	pb.BinaryExpression_DIV:         "\\",
	pb.BinaryExpression_MOD:         "%",
}

const precedenceOrExpression int8 = 1
const precedenceAndExpression int8 = 2

// Operators AT, IN, MATCHES and CONTAINS do not have a specified precedence.
// In those cases, the maximum precedence value should be assumed to prevent
// adding unnecessary parenthesis.
var binaryOperatorsPrecedence = map[pb.BinaryExpression_Operator]int8{
	pb.BinaryExpression_BITWISE_OR:  3,
	pb.BinaryExpression_XOR:         4,
	pb.BinaryExpression_BITWISE_AND: 5,
	pb.BinaryExpression_EQ:          6,
	pb.BinaryExpression_NEQ:         6,
	pb.BinaryExpression_LT:          7,
	pb.BinaryExpression_LE:          7,
	pb.BinaryExpression_GT:          7,
	pb.BinaryExpression_GE:          7,
	pb.BinaryExpression_SHIFT_LEFT:  8,
	pb.BinaryExpression_SHIFT_RIGHT: 8,
	pb.BinaryExpression_PLUS:        9,
	pb.BinaryExpression_MINUS:       9,
	pb.BinaryExpression_TIMES:       10,
	pb.BinaryExpression_DIV:         10,
	pb.BinaryExpression_MOD:         10,
}

const precedenceNotExpression int8 = 15
const precedenceUnaryExpression int8 = 15

func getExpressionPrecedence(e *pb.Expression) int8 {
	switch e.GetExpression().(type) {
	case *pb.Expression_OrExpression:
		return precedenceOrExpression
	case *pb.Expression_AndExpression:
		return precedenceAndExpression
	case *pb.Expression_BinaryExpression:
		return getBinaryExpressionPrecedence(e.GetBinaryExpression())
	case *pb.Expression_NotExpression:
		return precedenceNotExpression
	case *pb.Expression_UnaryExpression:
		return precedenceUnaryExpression
	default:
		// Expression with no precedence defined. Return maximum value.
		return math.MaxInt8
	}
}

func getBinaryExpressionPrecedence(e *pb.BinaryExpression) int8 {
	prec, ok := binaryOperatorsPrecedence[e.GetOperator()]
	if !ok {
		return math.MaxInt8
	}

	return prec
}

// Serializes a complete YARA ruleset.
func (ys *YaraSerializer) serializeRuleSet(rs *pb.RuleSet) error {
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
func (ys *YaraSerializer) serializeRule(r *pb.Rule) error {
	if err := ys.writeString("\n"); err != nil {
		return err
	}

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

	if err := ys.writeString("\n}\n"); err != nil {
		return err
	}

	return nil
}

// Serializes the "meta:" section in a YARA rule.
func (ys *YaraSerializer) serializeMetas(ms []*pb.Meta) error {
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
func (ys *YaraSerializer) serializeMeta(m *pb.Meta) error {
	switch val := m.GetValue().(type) {
	case *pb.Meta_Text:
		return ys.writeString(fmt.Sprintf(`%s = "%s"`, m.GetKey(), m.GetText()))
	case *pb.Meta_Number:
		return ys.writeString(fmt.Sprintf(`%s = %v`, m.GetKey(), m.GetNumber()))
	case *pb.Meta_Boolean:
		return ys.writeString(fmt.Sprintf(`%s = %v`, m.GetKey(), m.GetBoolean()))
	default:
		return fmt.Errorf(`Unsupported Meta value type "%T"`, val)
	}
}

// Serializes the "strings:" section in a YARA rule.
func (ys *YaraSerializer) serializeStrings(strs []*pb.String) error {
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

func (ys *YaraSerializer) serializeString(str *pb.String) error {
	if err := ys.writeString(fmt.Sprintf("%s = ", str.GetId())); err != nil {
		return err
	}

	return ys.SerializeStringValue(str)
}

// Serializes the value of a string in a YARA rule.
func (ys *YaraSerializer) SerializeStringValue(str *pb.String) error {
	switch val := str.GetValue().(type) {
	case *pb.String_Text:
		return ys.serializeTextString(str.GetText())
	case *pb.String_Hex:
		return ys.serializeHexString(str.GetHex())
	case *pb.String_Regexp:
		if err := ys.serializeRegexp(str.GetRegexp()); err != nil {
			return err
		}
		return ys.serializeStringModifiers(str.GetRegexp().Modifiers)
	default:
		return fmt.Errorf(`Unsupported String value type "%T"`, val)
	}

	return nil
}

func (ys *YaraSerializer) serializeTextString(t *pb.TextString) error {
	literal := fmt.Sprintf(`"%s"`, ast.Escape(t.GetText()))
	if err := ys.writeString(literal); err != nil {
		return err
	}
	return ys.serializeStringModifiers(t.Modifiers)
}

// Serialize for StringModifiers creates a space-separated list of
// string modifiers, excluding the i and s which are appended to /regex/
func (ys *YaraSerializer) serializeStringModifiers(m *pb.StringModifiers) error {
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
	if m.GetBase64() {
		alphabet := m.GetBase64Alphabet()
		if alphabet != "" {
			modifiers = append(modifiers, fmt.Sprintf("base64(\"%s\")", alphabet))
		} else {
			modifiers = append(modifiers, "base64")
		}
	}
	if m.GetBase64Wide() {
		alphabet := m.GetBase64Alphabet()
		if alphabet != "" {
			modifiers = append(modifiers, fmt.Sprintf("base64wide(\"%s\")", alphabet))
		} else {
			modifiers = append(modifiers, "base64wide")
		}
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

func (ys *YaraSerializer) serializeHexString(h *pb.HexTokens) error {
	if err := ys.writeString("{ "); err != nil {
		return err
	}

	if err := ys.serializeHexTokens(h); err != nil {
		return err
	}

	return ys.writeString("}")
}

func (ys *YaraSerializer) serializeHexTokens(ts *pb.HexTokens) error {
	for _, t := range ts.Token {
		if err := ys.serializeHexToken(t); err != nil {
			return err
		}
	}

	return nil
}

func (ys *YaraSerializer) serializeHexToken(t *pb.HexToken) error {
	switch val := t.GetValue().(type) {
	case *pb.HexToken_Sequence:
		return ys.serializeBytesSequence(t.GetSequence())
	case *pb.HexToken_Jump:
		return ys.serializeJump(t.GetJump())
	case *pb.HexToken_Alternative:
		return ys.serializeHexAlternative(t.GetAlternative())
	default:
		return fmt.Errorf(`Unsupported HexToken type: "%T"`, val)
	}
}

func (ys *YaraSerializer) serializeBytesSequence(b *pb.BytesSequence) error {
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

func (ys *YaraSerializer) serializeJump(jump *pb.Jump) error {
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

func (ys *YaraSerializer) serializeHexAlternative(alt *pb.HexAlternative) error {
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

func (ys *YaraSerializer) serializePercentage(p *pb.Percentage) error {
	if err := ys.SerializeExpression(p.Expression); err != nil {
		return err
	}
	if err := ys.writeString("%"); err != nil {
		return err
	}
	return nil
}

// SerializeExpression serializes an Expression in a YARA rule condition.
func (ys *YaraSerializer) SerializeExpression(e *pb.Expression) error {
	switch val := e.GetExpression().(type) {
	case *pb.Expression_BoolValue:
		return ys.writeString(fmt.Sprintf("%v", e.GetBoolValue()))
	case *pb.Expression_OrExpression:
		return ys.serializeOrExpression(e.GetOrExpression())
	case *pb.Expression_AndExpression:
		return ys.serializeAndExpression(e.GetAndExpression())
	case *pb.Expression_StringIdentifier:
		return ys.writeString(e.GetStringIdentifier())
	case *pb.Expression_ForInExpression:
		return ys.serializeForInExpression(e.GetForInExpression())
	case *pb.Expression_ForOfExpression:
		return ys.serializeForOfExpression(e.GetForOfExpression())
	case *pb.Expression_BinaryExpression:
		return ys.serializeBinaryExpression(e.GetBinaryExpression())
	case *pb.Expression_Text:
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
	case *pb.Expression_NumberValue:
		return ys.writeString(fmt.Sprintf("%d", e.GetNumberValue()))
	case *pb.Expression_DoubleValue:
		return ys.writeString(fmt.Sprintf("%f", e.GetDoubleValue()))
	case *pb.Expression_Range:
		return ys.serializeRange(e.GetRange())
	case *pb.Expression_Keyword:
		return ys.serializeKeyword(e.GetKeyword())
	case *pb.Expression_Identifier:
		return ys.serializeIdentifier(e.GetIdentifier())
	case *pb.Expression_Regexp:
		return ys.serializeRegexp(e.GetRegexp())
	case *pb.Expression_NotExpression:
		return ys.serializeNotExpression(e.GetNotExpression())
	case *pb.Expression_IntegerFunction:
		return ys.serializeIntegerFunction(e.GetIntegerFunction())
	case *pb.Expression_StringOffset:
		return ys.serializeStringOffset(e.GetStringOffset())
	case *pb.Expression_StringLength:
		return ys.serializeStringLength(e.GetStringLength())
	case *pb.Expression_StringCount:
		return ys.writeString(e.GetStringCount())
	case *pb.Expression_PercentageExpression:
		return ys.serializePercentage(e.GetPercentageExpression())
	default:
		return fmt.Errorf(`Unsupported Expression type "%T"`, val)
	}
}

// Serializes an OR expression.
func (ys *YaraSerializer) serializeOrExpression(es *pb.Expressions) error {
	return ys.serializeTerms(es.Terms, " or ", precedenceOrExpression)
}

// Serializes an AND expression.
func (ys *YaraSerializer) serializeAndExpression(es *pb.Expressions) error {
	return ys.serializeTerms(es.Terms, " and ", precedenceAndExpression)
}

func (ys *YaraSerializer) serializeTerms(terms []*pb.Expression, joinStr string, precedence int8) error {
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
func (ys *YaraSerializer) serializeForInExpression(e *pb.ForInExpression) error {
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
func (ys *YaraSerializer) serializeForExpression(e *pb.ForExpression) error {
	switch val := e.GetFor().(type) {
	case *pb.ForExpression_Expression:
		return ys.SerializeExpression(e.GetExpression())
	case *pb.ForExpression_Keyword:
		return ys.serializeForKeyword(e.GetKeyword())
	default:
		return fmt.Errorf(`Unsupported ForExpression value type "%s"`, val)
	}
}

func (ys *YaraSerializer) serializeIterator(e *pb.Iterator) error {
	switch val := e.GetIterator().(type) {
	case *pb.Iterator_IntegerSet:
		return ys.serializeIntegerSet(e.GetIntegerSet())
	case *pb.Iterator_Identifier:
		return ys.serializeIdentifier(e.GetIdentifier())
	default:
		return fmt.Errorf(`Unsupported Iterator value type "%s"`, val)
	}
}

// Serializes an IntegerSet.
func (ys *YaraSerializer) serializeIntegerSet(e *pb.IntegerSet) error {
	switch val := e.GetSet().(type) {
	case *pb.IntegerSet_IntegerEnumeration:
		return ys.serializeIntegerEnumeration(e.GetIntegerEnumeration())
	case *pb.IntegerSet_Range:
		return ys.serializeRange(e.GetRange())
	default:
		return fmt.Errorf(`Unsupported IntegerSet value type "%s"`, val)
	}
}

// Serializes an IntegerEnumeration.
func (ys *YaraSerializer) serializeIntegerEnumeration(e *pb.IntegerEnumeration) error {
	if err := ys.writeString("("); err != nil {
		return err
	}

	if err := ys.serializeTerms(e.Values, ", ", math.MinInt8); err != nil {
		return err
	}

	return ys.writeString(")")
}

// Serializes a Range expression.
func (ys *YaraSerializer) serializeRange(e *pb.Range) error {
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
func (ys *YaraSerializer) serializeForOfExpression(e *pb.ForOfExpression) error {
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

	if e.GetRange() != nil {
		if err := ys.writeString(" in "); err != nil {
			return err
		}
		if err := ys.serializeRange(e.Range); err != nil {
			return err
		}
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
func (ys *YaraSerializer) serializeStringSet(e *pb.StringSet) error {
	switch val := e.GetSet().(type) {
	case *pb.StringSet_Strings:
		return ys.serializeStringEnumeration(e.GetStrings())
	case *pb.StringSet_Keyword:
		return ys.serializeStringSetKeyword(e.GetKeyword())
	default:
		return fmt.Errorf(`Unsupported StringSet value type "%s"`, val)
	}
}

// Serializes a StringEnumeration.
func (ys *YaraSerializer) serializeStringEnumeration(e *pb.StringEnumeration) error {
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
func (ys *YaraSerializer) serializeKeyword(e pb.Keyword) error {
	kw, ok := keywords[e]
	if !ok {
		return fmt.Errorf(`Unknown keyword "%v"`, e)
	}

	return ys.writeString(kw)
}

// Serializes a ForKeyword.
func (ys *YaraSerializer) serializeForKeyword(e pb.ForKeyword) error {
	kw, ok := forKeywords[e]
	if !ok {
		return fmt.Errorf(`Unknown keyword "%v"`, e)
	}

	return ys.writeString(kw)
}

// Serializes a StringSetKeyword.
func (ys *YaraSerializer) serializeStringSetKeyword(e pb.StringSetKeyword) error {
	kw, ok := stringSetKeywords[e]
	if !ok {
		return fmt.Errorf(`Unknown keyword "%v"`, e)
	}

	return ys.writeString(kw)
}

// Serializes a BinaryExpression.
func (ys *YaraSerializer) serializeBinaryExpression(e *pb.BinaryExpression) error {
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
func (ys *YaraSerializer) serializeIdentifier(i *pb.Identifier) error {
	for i, item := range i.GetItems() {
		switch val := item.GetItem().(type) {
		case *pb.Identifier_IdentifierItem_Identifier:
			if i > 0 {
				if err := ys.writeString("."); err != nil {
					return err
				}
			}
			if err := ys.writeString(item.GetIdentifier()); err != nil {
				return err
			}
		case *pb.Identifier_IdentifierItem_Index:
			if err := ys.writeString("["); err != nil {
				return err
			}
			if err := ys.SerializeExpression(item.GetIndex()); err != nil {
				return err
			}

			if err := ys.writeString("]"); err != nil {
				return err
			}
		case *pb.Identifier_IdentifierItem_Arguments:
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
func (ys *YaraSerializer) serializeRegexp(r *pb.Regexp) error {
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
func (ys *YaraSerializer) serializeNotExpression(e *pb.Expression) error {
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
func (ys *YaraSerializer) serializeIntegerFunction(e *pb.IntegerFunction) error {
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
func (ys *YaraSerializer) serializeStringOffset(e *pb.StringOffset) error {
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
func (ys *YaraSerializer) serializeStringLength(e *pb.StringLength) error {
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
