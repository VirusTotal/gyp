package utils

import (
	"testing"

	"github.com/VirusTotal/gyp"
	"github.com/VirusTotal/gyp/ast"
	"github.com/google/go-cmp/cmp"
)

func TestMultipleInLoopWithIdents(t *testing.T) {
	condition := `false or for any i in (1..5):(true) and for any z in (1..5): (true or foo)`
	expected := map[string]int{"foo": 0}
	testGetYARARuleDependencies(t, condition, expected)
}

func TestNestedInLoopWithIdents(t *testing.T) {
	condition := `b or false or for any i in (1..5):(true and for any z in (1..5): (true or foo))`
	expected := map[string]int{"b": 0, "foo": 0}
	testGetYARARuleDependencies(t, condition, expected)
}

func TestInLoopWithIdents(t *testing.T) {
	condition := `foo_zz and for any i in (1..5): (foo and uint32(filesize - (i * 0x100) - 4) == (i * 0x00000100) + 4 and uint32(filesize - (i * 0x100)) == 0x10)`
	expected := map[string]int{"foo_zz": 0, "foo": 0}
	testGetYARARuleDependencies(t, condition, expected)
}

func TestInLoopWithNoIdents(t *testing.T) {
	condition := `foo_zz and for any i in (1..5): (uint32(filesize - (i * 0x100) - 4) == (i * 0x00000100) + 4 and uint32(filesize - (i * 0x100)) == 0x10)`
	expected := map[string]int{"foo_zz": 0}
	testGetYARARuleDependencies(t, condition, expected)
}

func TestLotsOfIdents(t *testing.T) {
	condition := `pe.exports("foo0")
    or pe.exports("foo1")
    or pe.exports("foo2")
    or pe.exports("foo3")`
	expected := map[string]int{"pe": 3}
	testGetYARARuleDependencies(t, condition, expected)
}

func TestThreeDupIdents(t *testing.T) {
	condition := `foo_zz or foo_zz or foo_zz or $a`
	expected := map[string]int{"foo_zz": 2}
	testGetYARARuleDependencies(t, condition, expected)
}

func TestOneIdents(t *testing.T) {
	condition := `foo_zz or $a`
	expected := map[string]int{"foo_zz": 0}
	testGetYARARuleDependencies(t, condition, expected)
}

func TestStrOffsetImport(t *testing.T) {
	condition := `$a at pe.entry_point`
	expected := map[string]int{"pe": 0}
	testGetYARARuleDependencies(t, condition, expected)
}

func TestNoIdents(t *testing.T) {
	condition := `all of ($a*) and ($a or $a)`
	expected := map[string]int{}
	testGetYARARuleDependencies(t, condition, expected)
}

func TestNotIdent(t *testing.T) {
	condition := `not foo_zz`
	expected := map[string]int{"foo_zz": 0}
	testGetYARARuleDependencies(t, condition, expected)
}

func TestNestedIdents(t *testing.T) {
	condition := `(foo_zz or foo_zz) and $a or ($a and (foo_xx or a))`
	expected := map[string]int{"foo_zz": 1, "foo_xx": 0, "a": 0}
	testGetYARARuleDependencies(t, condition, expected)
}

func TestSingleDupIdent(t *testing.T) {
	condition := `(foo_zz or foo_zz)`
	expected := map[string]int{"foo_zz": 1}
	testGetYARARuleDependencies(t, condition, expected)
}

func TestSingleGroupIdent(t *testing.T) {
	condition := `(foo_zz)`
	expected := map[string]int{"foo_zz": 0}
	testGetYARARuleDependencies(t, condition, expected)
}

func TestSingleIdent(t *testing.T) {
	condition := `foo_zz`
	expected := map[string]int{"foo_zz": 0}
	testGetYARARuleDependencies(t, condition, expected)
}

func testGetYARARuleDependencies(t *testing.T, condition string, expected map[string]int) {
	rulestr := "rule foo {strings:$a = \"test\" condition:" + condition + "}"
	ruleset, err := gyp.ParseString(rulestr)
	if err != nil {
		t.Errorf("Unable to parse rule")
	}
	results := GetRuleIdentifiers(*ruleset.Rules[0])
	if ok := cmp.Equal(results, expected); ok == false {
		t.Errorf("Condition not extracted correctly. Expected %v, but got %v", expected, results)
	}
}

func TestAddToIdentMapWithIgnoreList(t *testing.T) {
	expected := map[string]int{}
	ident := ast.Identifier{Identifier: "foo"}
	ruleIdentifiers := make(map[string]int)
	ignoreList := []string{"foo"}
	addToIdentMap(&ident, ruleIdentifiers, ignoreList)
	if ok := cmp.Equal(ruleIdentifiers, expected); ok == false {
		t.Errorf("Expected %v but got %v", expected, ruleIdentifiers)
	}
}

func TestAddToIdentMap(t *testing.T) {
	expected := map[string]int{"foo": 0}
	ident := ast.Identifier{Identifier: "foo"}
	ruleIdentifiers := make(map[string]int)
	ignoreList := []string{""}
	addToIdentMap(&ident, ruleIdentifiers, ignoreList)
	if ok := cmp.Equal(ruleIdentifiers, expected); ok == false {
		t.Errorf("Expected %v but got %v", expected, ruleIdentifiers)
	}
}

func TestAddNodeGrpIdentifierToIdentifiersMap(t *testing.T) {
	ruleset, err := gyp.ParseString("rule foo { condition:(foo)}")
	if err != nil {
		t.Fatalf("Unable to parse rule")
	}
	expected := map[string]int{"foo": 0}
	ruleIdentifiers := GetRuleIdentifiers(*ruleset.Rules[0])
	if ok := cmp.Equal(ruleIdentifiers, expected); ok == false {
		t.Errorf("Expected %v but got %v", expected, ruleIdentifiers)
	}
}

func TestAddNodeChildrenToQue(t *testing.T) {
	ruleset, err := gyp.ParseString("rule foo {condition:test and test2}")
	if err != nil {
		t.Fatalf("Unable to parse rule")
	}
	queue := append([]queueT{}, queueT{node: ruleset.Rules[0].Condition})
	addNodeChildrenToQue(&queue)
	if len(queue) != 3 {
		t.Fatalf("Did not add node children to queue")
	}
}

func TestSliceContains(t *testing.T) {
	animals := []string{"cat", "dog", "bird"}
	testStrs := []string{"fish", "d0g"}
	for _, testStr := range testStrs {
		if ok := sliceContains(testStr, animals); ok {
			t.Fatalf("sliceContains is reporting that %s exists in %v", testStr, animals)
		}
	}
	if ok := sliceContains("dog", animals); !ok {
		t.Fatalf("sliceContains is reporting that %s does not exist in %v", "dog", animals)
	}
}

func TestGetDependenciesForRules(t *testing.T) {
	rulestr := `rule woo {condition:false} rule test {strings: $wooo = "1" condition:foo_zz or $wooo} rule test2 {strings: $gazunder = "woo" condition: wxs or pe.imports and wxs or wxs or wxs or foo and $gazunder or test or woo}`
	ruleset, err := gyp.ParseString(rulestr)
	if err != nil {
		t.Fatalf("Unable to parse rules: %s", err)
	}
	dependencies, err := GetDependenciesForRules(*ruleset, "test2")
	if err != nil {
		t.Fatalf("GetDependenciesForRules returned an error (%s)", err.Error())
	}
	expectedImports := []string{"pe"}
	expectedRules := []string{"woo", "test"}

	if !cmp.Equal(expectedImports, dependencies.Imports) || len(dependencies.Rules) != 2 {
		t.Fatalf("expected %+v, but got %+v", expectedImports, dependencies)
	}
	for _, rule := range dependencies.Rules {
		if !sliceContains(rule.Identifier, expectedRules) {
			t.Fatalf("expected %+v, but %s was not found", expectedRules, rule.Identifier)
		}
	}
}

func TestGetDependenciesForRulesEmptyRuleset(t *testing.T) {
	_, err := GetDependenciesForRules(ast.RuleSet{}, "test2")
	if err.Error() != "ruleset does not contain any rules" {
		t.Fatalf("Empty ruleset was provied to GetDependenciesForRules, but no error was thrown")
	}
}

func TestGetDependenciesForRulesMissingFromRuleset(t *testing.T) {
	rulestr := `rule woo {condition:false} rule test {condition:foo_zz or $wooo}`
	ruleset, _ := gyp.ParseString(rulestr)
	_, err := GetDependenciesForRules(*ruleset, "foo")
	if err.Error() != "foo does not exist in the ruleset" {
		t.Fatalf("Empty ruleset was provied to GetDependenciesForRules, but no error was thrown")
	}
}

func TestGetDependencyChainForRules(t *testing.T) {
	expectedImports := []string{"pe"}
	expectedRules := []string{"z", "c", "a"}
	rules := `rule a {condition:false or c} rule b {condition:false or a} rule c {condition:false and pe.exports and z} rule d {condition:false or b} rule z {condition:true}`
	ruleset, _ := gyp.ParseString(rules)
	rChain, err := GetDependencyChainForRules(*ruleset, true, "b")
	if err != nil {
		t.Fatalf(err.Error())
	}
	if !cmp.Equal(rChain.Imports, expectedImports) {
		t.Fatalf("Expected %v, but got %v", expectedImports, rChain.Imports)
	}
	ruleNames := []string{}
	for _, rules := range rChain.Rules {
		ruleNames = append(ruleNames, rules.Identifier)
		if rules.Private != true {
			t.Fatalf("Expected private rule")
		}
	}
	if !cmp.Equal(ruleNames, expectedRules) {
		t.Fatalf("Expected %v, but got %v", expectedRules, ruleNames)
	}
}

func TestGetDependencyChainErr(t *testing.T) {
	rules := `rule a {condition:false or c} rule b {condition:false or a} rule c {condition:false or b and pe.exports} rule d {condition:false or b}`
	ruleset, _ := gyp.ParseString(rules)
	_, err := GetDependencyChainForRules(*ruleset, false, "woo")
	if err.Error() != "woo does not exist in the ruleset" {
		t.Fatalf("Empty ruleset was provied to GetDependenciesForRules, but no error was thrown")
	}
}

func TestAddNilNodeToQue(t *testing.T) {
	nkr := `
	rule foo_x {
		condition:
			true
	  }
	rule foo_y {
		strings:
		  $foo = "foo"
		  $foo2 = "foo2"
		condition:
		  foo_x and
		  (
			$foo in (@foo2 - 100..@foo2 + 100)
		  )
	  }`
	nrs, _ := gyp.ParseString(string(nkr))
	results, _ := GetDependencyChainForRules(*nrs, true, "foo_y")
	expected := "foo_x"
	if results.Rules[0].Identifier != expected {
		t.Fatalf("Did not get expected value (%s)", expected)
	}
}
