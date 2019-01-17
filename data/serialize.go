// Functions and methods for reserializing the JSON into YARA rules.
// TODO: Handle indents better... Maybe have a global var denoting
// how many spaces to indent.
// TODO: Handle indents and formatting in general for conditions.
// Once conditions are treated as first-class vs. text, we can do that.

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
	if r.Modifiers.Global {
		b.WriteString("global ")
	}
	if r.Modifiers.Private {
		b.WriteString("private ")
	}

	// Rule name
	b.WriteString(fmt.Sprintf("rule %s ", r.Identifier))

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

	metas, err := r.Meta.Serialize()
	if err != nil {
		return
	}
	b.WriteString(metas)

	strs, err := r.Strings.Serialize()
	if err != nil {
		return
	}
	b.WriteString(strs)

	b.WriteString("condition:\n")
	b.WriteString("  ") // TODO: Don't assume indent...
	b.WriteString(r.Condition.String())
	b.WriteString("\n}\n\n")

	out = b.String()

	return
}

// Serialize for Metas returns the "meta:" section in the YARA rule
func (ms *Metas) Serialize() (out string, err error) {
	if ms == nil || len(*ms) == 0 {
		return
	}

	var b strings.Builder
	b.WriteString("meta:\n")

	for _, m := range *ms {
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
	switch val := m.Val.(type) {
	case string:
		out = fmt.Sprintf(`%s = "%s"`, m.Key, val)

	case int64, bool:
		out = fmt.Sprintf(`%s = %v`, m.Key, val)

	case float64:
		// This is a bit tricky... val is interface{} and JSON unmarshals it
		// as float64... So ensure decimal part is zero and treat as int64.
		n := int64(val)
		check := val - float64(n) // This should be 0.0 if it was int64
		if check != 0.0 {
			err = fmt.Errorf(`Unsupported meta value type "%T"`, val)
			return
		}
		out = fmt.Sprintf(`%s = %v`, m.Key, val)

	default:
		err = fmt.Errorf(`Unsupported meta value type "%s"`, val)
	}

	return
}

// Serialize for Strings returns the "strings:" section in the YARA rule
func (ss *Strings) Serialize() (out string, err error) {
	if ss == nil || len(*ss) == 0 {
		return
	}

	var b strings.Builder
	b.WriteString("strings:\n")

	for _, s := range *ss {
		str, e := s.Serialize()
		if e != nil {
			err = e
			return
		}
		b.WriteString("  ") // TODO: Make indent customizable
		b.WriteString(str)
		b.WriteRune('\n')
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
	switch t := s.Type; t {
	case TypeString:
		encapsOpen, encapsClose = `"`, `"`

	case TypeHexString:
		encapsOpen, encapsClose = "{", "}"

	case TypeRegex:
		encapsOpen = "/"
		var closeBuilder strings.Builder
		closeBuilder.WriteRune('/')
		if s.Modifiers.I {
			closeBuilder.WriteRune('i')
		}
		if s.Modifiers.S {
			closeBuilder.WriteRune('s')
		}
		encapsClose = closeBuilder.String()

	default:
		err = fmt.Errorf("No such string type %s (%d)", t, t)
		return
	}

	mods, _ := s.Modifiers.Serialize()

	out = fmt.Sprintf(format, s.ID, encapsOpen, s.Text, encapsClose, mods)

	return
}

// Serialize for StringModifiers creates a space-sparated list of
// string modifiers, excluding the i and s which are appended to /regex/
// The returned error must be nil.
func (m *StringModifiers) Serialize() (out string, _ error) {
	const modsAvailable = 4
	modifiers := make([]string, 0, modsAvailable)
	if m.ASCII {
		modifiers = append(modifiers, "ascii")
	}
	if m.Wide {
		modifiers = append(modifiers, "wide")
	}
	if m.Nocase {
		modifiers = append(modifiers, "nocase")
	}
	if m.Fullword {
		modifiers = append(modifiers, "fullword")
	}
	if m.Xor {
		modifiers = append(modifiers, "xor")
	}

	out = strings.Join(modifiers, " ")
	return
}
