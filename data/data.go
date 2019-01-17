package data

// RuleSet represents the contents of a yara file
type RuleSet struct {
	File     string   `json:"file"` // Name of the yara file
	Imports  []string `json:"imports"`
	Includes []string `json:"includes"`
	Rules    []Rule   `json:"rules"`
}

// A Rule is a single yara rule
type Rule struct {
	Modifiers  RuleModifiers          `json:"modifiers"`
	Identifier string                 `json:"identifier"`
	Tags       []string               `json:"tags"`
	Meta       Metas                  `json:"meta"`
	Strings    Strings                `json:"strings"`
	Condition  BooleanExpressionTerm  `json:"condition"`
}

// RuleModifiers denote whether a Rule is global, private, neither, or both.
type RuleModifiers struct {
	Global  bool `json:"global"`
	Private bool `json:"private"`
}

// Metas are slices of Meta. A single Meta may be duplicated within Metas.
type Metas []Meta

// A Meta is a simple key/value pair. Val should be restricted to
// int, string, and bool.
type Meta struct {
	Key string      `json:"key"`
	Val interface{} `json:"val"`
}

// Strings are slices of String. No two String structs may have the same
// identifier within a Strings, except for the $ anonymous identifier.
type Strings []String

// String is a string, regex, or byte pair sequence
type String struct {
	ID        string          `json:"id"`
	Type      StringType      `json:"type"`
	Text      string          `json:"text"`
	Modifiers StringModifiers `json:"modifiers"`
}

// StringType is used to differentiate between string, hex bytes, and regex
type StringType int

// Type of String
const (
	TypeString StringType = iota
	TypeHexString
	TypeRegex
)

// StringModifiers denote the status of the possible modifiers for strings
type StringModifiers struct {
	Nocase   bool `json:"nocase"`
	ASCII    bool `json:"ascii"`
	Wide     bool `json:"wide"`
	Fullword bool `json:"fullword"`
	Xor      bool `json:"xor"`
	I        bool `json:"i"` // for regex
	S        bool `json:"s"` // for regex
}

type Regexp struct {
  Text string
  Modifiers StringModifiers
}
