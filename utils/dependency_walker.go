package utils

import (
	"fmt"

	"github.com/VirusTotal/gyp/ast"
)

var yaraModules = []string{"pe", "elf", "cuckoo", "magic", "hash", "math", "dotnet", "time"}

type queueT struct {
	node       ast.Node
	ignoreList []string
}

// GetDependencyChainForRules will recursively find dependencies for a list of rules
// returnDepAsPrivate will dictate if dependent rules are marked as private
func GetDependencyChainForRules(ruleset ast.RuleSet, returnDepAsPrivate bool, ruleNames ...string) (ast.RuleSet, error) {
	queue := make(map[string]struct{}) // List of rules to get dependencies for
	processed := []string{}            // List of rules where dependencies have already been found
	results := ast.RuleSet{}
	for _, ruleName := range ruleNames {
		queue[ruleName] = struct{}{}
	}

	for len(queue) > 0 {
		for k := range queue {
			dependencies, err := GetDependenciesForRules(ruleset, k)
			if err != nil {
				return ast.RuleSet{}, err
			}
			for _, rule := range dependencies.Rules {
				if _, ok := queue[rule.Identifier]; !ok && !sliceContains(rule.Identifier, processed) {
					if returnDepAsPrivate {
						rule.Private = true
					}
					results.Rules = append(results.Rules, rule)
					queue[rule.Identifier] = struct{}{}
				}
			}
			for _, imprt := range dependencies.Imports {
				if !sliceContains(imprt, results.Imports) {
					results.Imports = append(results.Imports, imprt)
				}
			}
			processed = append(processed, k)
			delete(queue, k)
		}
	}
	final := OrderRules(results)
	return final, nil
}

// OrderRules will take in a ruleset and ensure the order of the rules is correct
func OrderRules(rs ast.RuleSet) ast.RuleSet {
	var goodOrder []*ast.Rule
	type nodeT struct {
		rule         *ast.Rule
		dependencies []string
	}
	var nodes []nodeT
	for _, rule := range rs.Rules {
		var node nodeT
		node.rule = rule
		drs, err := GetDependenciesForRules(rs, rule.Identifier)
		if err != nil {
			panic(err.Error())
		}
		for _, dr := range drs.Rules {
			node.dependencies = append(node.dependencies, dr.Identifier)
		}
		nodes = append(nodes, node)
	}

	for len(goodOrder) != len(rs.Rules) {
		for i := len(nodes) - 1; i >= 0; i-- {
			node := nodes[i]
			if len(node.dependencies) == 0 {
				// Rule has no dependencies
				goodOrder = append([]*ast.Rule{node.rule}, goodOrder...) // Add to goodOrder
				nodes = append(nodes[:i], nodes[i+1:]...)                // Delete from nodes
				continue
			}
			var curDepBuffer []string // Contains list of rules already in the rule buffer
			for _, gor := range goodOrder {
				curDepBuffer = append(curDepBuffer, gor.Identifier)
			}
			if len(curDepBuffer) < len(node.dependencies) {
				// Not enough rules exist for all dependencies to be there, skip to next rule
				continue
			}
			var dc int
			for _, dep := range node.dependencies {
				if sliceContains(dep, curDepBuffer) {
					dc++
				}
			}
			if dc == len(node.dependencies) {
				// All dependencies are there, place rule on the buffer
				goodOrder = append(goodOrder, node.rule)  // Add to goodOrder buffer
				nodes = append(nodes[:i], nodes[i+1:]...) // Delete from nodes
				continue
			}

		}
	}
	rs.Rules = goodOrder
	return rs
}

// GetDependenciesForRules will find all the dependencies (rules & modules)
// for a slice of YARA rules
func GetDependenciesForRules(ruleset ast.RuleSet, ruleNames ...string) (ast.RuleSet, error) {
	// Make sure ruleNames and ruleset are not empty
	if len(ruleset.Rules) == 0 {
		return ast.RuleSet{}, fmt.Errorf("ruleset does not contain any rules")
	}

	// Ensure ruleNames are unique
	ruleNamesM := make(map[string]struct{})
	for _, ruleName := range ruleNames {
		ruleNamesM[ruleName] = struct{}{}
	}

	var dependencies ast.RuleSet
	for ruleName := range ruleNamesM {
		var rule ast.Rule
		for i := range ruleset.Rules {
			if ruleset.Rules[i].Identifier == ruleName {
				rule = *ruleset.Rules[i]
				break
			}
		}
		if rule.Identifier == "" {
			return ast.RuleSet{}, fmt.Errorf("%s does not exist in the ruleset", ruleName)
		}
		ruleIdents := GetRuleIdentifiers(rule)
		for ident := range ruleIdents {
			// Get Imports
			if sliceContains(ident, yaraModules) {
				dependencies.Imports = append(dependencies.Imports, ident)
			} else {
				// Get Rules
				for _, rule := range ruleset.Rules {
					if rule.Identifier == ident {
						rule := *rule
						dependencies.Rules = append(dependencies.Rules, &rule)
						break
					}
				}
			}
		}
	}
	return dependencies, nil
}

// GetRuleIdentifiers will find all the identifiers (excluding ForLoop
// variables and Builtin FuncCalls) and the number of times each identifier is
// seen for a given YARA rule
func GetRuleIdentifiers(rule ast.Rule) map[string]int {
	ruleIdentifiers := make(map[string]int)                   // ruleIdentifiers contains [identifier]numOfTimesSeen
	queue := append([]queueT{}, queueT{node: rule.Condition}) // queue contains all the nodes to be processed
	for len(queue) > 0 {
		queueItem := &queue[0]
		if _, ok := queueItem.node.(*ast.ForIn); ok {
			// ForIn node found, extract loop variables and add them to the ignoreList
			varsToIgnore := queueItem.node.(*ast.ForIn).Variables
			queueItem.ignoreList = append(queueItem.ignoreList, varsToIgnore...)
		}
		if funcCall, ok := queueItem.node.(*ast.FunctionCall); ok {
			if funcCall.Builtin {
				// Builtin FunctionCall node found, add it's identifier to the ignoreList
				x := funcCall.Callable.(*ast.Identifier).Identifier
				queueItem.ignoreList = append(queueItem.ignoreList, x)
			}
		}
		addNodeIdentifierToIdentifiersMap(&queue, ruleIdentifiers)
		addNodeChildrenToQue(&queue)
		queue = append(queue[:0], queue[1:]...) // Delete node from queue
	}
	return ruleIdentifiers
}

// addNodeChildrenToQue adds a nodes children to the queue
func addNodeChildrenToQue(queue *[]queueT) {
	queueItem := &(*queue)[0]
	if queueItem.node == nil {
		// If node is nil, it can't have children to add to the queue
		return
	}
	for _, childNode := range queueItem.node.Children() {
		*queue = append(*queue, queueT{node: childNode, ignoreList: queueItem.ignoreList})
	}
}

// addNodeIdentifierToIdentifiersMap will find the current node identifier and then add it to the ruleIdentifiers map
func addNodeIdentifierToIdentifiersMap(queue *[]queueT, ruleIdentifiers map[string]int) {
	queueItem := &(*queue)[0]
	if ident, ok := queueItem.node.(*ast.Identifier); ok {
		addToIdentMap(ident, ruleIdentifiers, queueItem.ignoreList)
	}
}

// addToIdentMap will record the Ident to the Ident map (assuming it is not in the nodes ignoreList)
func addToIdentMap(ident *ast.Identifier, ruleIdentifiers map[string]int, ignoreList []string) {
	if sliceContains(ident.Identifier, ignoreList) {
		return
	}
	if v, ok := ruleIdentifiers[ident.Identifier]; ok {
		v++
		ruleIdentifiers[ident.Identifier] = v
	} else {
		ruleIdentifiers[ident.Identifier] = 0
	}
}

// sliceContains checks to see if a string exists in a slice
func sliceContains(str string, s []string) bool {
	for i := range s {
		if str == s[i] {
			return true
		}
	}
	return false
}
