package tests

import (
  "log"
  "os"
  "strings"
  "testing"

  "github.com/VirusTotal/go-yara-parser/data"
  "github.com/VirusTotal/go-yara-parser/grammar"
)

const testfile = "ruleset.yar"

var ruleset *data.RuleSet

func init() {
  f, err := os.Open(testfile)
  if err != nil {
    log.Fatalf(`Unable to open ruleset file "%s": %s`, testfile, err)
  }
  rs, err := grammar.Parse(f, os.Stderr)
  if err != nil {
    log.Fatalf(`Unable to parse ruleset file "%s": %s`, testfile, err)
  }

  ruleset = &rs
}

// TestRuleNames verifies rule names are being collected
func TestRuleNames(t *testing.T) {

  const ruleName = "BASIC_BOOL"

  for _, rule := range ruleset.Rules {
    if rule.GetIdentifier() == ruleName {
      return
    }
  }

  t.Fatalf(`Ruleset "%s" has no rule named "%s"`, testfile, ruleName)
}

// TestImport verifies imports are being collected
func TestImport(t *testing.T) {

  const i = 1
  if l := len(ruleset.Imports); l < i {
    t.Fatalf("Expected > %d imports in file %s; found %d", i, testfile, l)
  }
}

// TestString verifies that strings are being collected
func TestString(t *testing.T) {

  const (
    ruleName = "STRING1"
    stringID = "$s1"
  )
  for _, rule := range ruleset.Rules {
    if rule.GetIdentifier() == ruleName {
      for _, s := range rule.Strings {
        if s.GetId() == stringID {
          return
        }
      }
      t.Fatalf(`Ruleset "%s" rule "%s" has no string "%s"`,
        testfile, ruleName, stringID)
    }
  }

  t.Fatalf(`Ruleset "%s" has no rule "%s" with string "%s"`,
    testfile, ruleName, stringID)
}

// TestGlobal verifies that the global modifier is being collected
func TestGlobal(t *testing.T) {

  const ruleName = "GLOBAL"
  for _, rule := range ruleset.Rules {
    if rule.GetIdentifier() == ruleName {
      if rule.Modifiers.GetGlobal() {
        return
      }
      t.Fatalf(`Ruleset "%s" contains rule "%s" which is not global`,
        testfile, ruleName)
    }
  }

  t.Fatalf(`Ruleset "%s" has no rule "%s"`, testfile, ruleName)
}

// TestPrivate verifies that the private modifier is being collected
func TestPrivate(t *testing.T) {

  const ruleName = "PRIVATE"
  for _, rule := range ruleset.Rules {
    if rule.GetIdentifier() == ruleName {
      if rule.Modifiers.GetPrivate() {
        return
      }
      t.Fatalf(`Ruleset "%s" contains rule "%s" which is not private`,
        testfile, ruleName)
    }
  }

  t.Fatalf(`Ruleset "%s" has no rule "%s"`, testfile, ruleName)
}

// TestMeta verifies that metadata is being collected
func TestMeta(t *testing.T) {

  const ruleName = "META"
  for _, rule := range ruleset.Rules {
    if rule.GetIdentifier() == ruleName {
      checklist := make(map[string]bool)
      for _, kvp := range rule.Meta {
        checklist[kvp.GetKey()] = true
      }

      expecteds := []string{
        "meta_str", "meta_int", "meta_neg", "meta_true", "meta_false",
      }

      for _, expected := range expecteds {
        if !checklist[expected] {
          t.Errorf(`Ruleset "%s" rule "%s" missing expected meta "%s"`,
            testfile, rule.GetIdentifier(), expected)
        }
      }
      return
    }
  }

  t.Fatalf(`Ruleset "%s" has no rule "%s"`, testfile, ruleName)
}

// TestXor verifies that the xor string modifier works
func TestXor(t *testing.T) {
  const ruleName = "XOR"
  for _, rule := range ruleset.Rules {
    if rule.GetIdentifier() == ruleName {
      for _, s := range rule.Strings {
        const strNamePrefix = "$xor"
        if strings.HasPrefix(s.GetId(), strNamePrefix) {
          if !s.Modifiers.GetXor() {
            t.Errorf(`Ruleset "%s" rule "%s" string "%s" xor modifier not found`,
              testfile, rule.GetIdentifier(), s.GetId())
          }
        } else {
          if s.Modifiers.GetXor() {
            t.Errorf(`Ruleset "%s" rule "%s" string "%s" has unexpected xor modifier`,
              testfile, rule.GetIdentifier(), s.GetId())
          }
        }
      }
    }
  }
}
