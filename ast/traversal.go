package ast

// A Visitor is a common interface implemented by all types of visitors.
type Visitor interface{}

// PreOrderVisitor is the interface that must be implemented by a visitor that
// wants to be notified about expressions before any of the expression's sub
// expressions is visited.
type PreOrderVisitor interface {
	Visitor
	PreOrderVisit(*Expression)
}

// PostOrderVisitor is the interface that must be implemented by a visitor that
// wants to be notified about expressions after all of the expression's sub
// expressions are visited.
type PostOrderVisitor interface {
	Visitor
	PostOrderVisit(*Expression)
}

// DepthFirstSearch performs a depth-first traversal of the expression's syntax
// tree, it receives a Visitor that must implement PreOrderVisitor, PostOrderVisitor
// or both.
func (e *Expression) DepthFirstSearch(v Visitor) {
	if e == nil {
		return
	}
	postOrder := func(v Visitor, e *Expression) {
		if pv, ok := v.(PostOrderVisitor); ok {
			pv.PostOrderVisit(e)
		}
	}
	preOrder := func(v Visitor, e *Expression) {
		if pv, ok := v.(PreOrderVisitor); ok {
			pv.PreOrderVisit(e)
		}
	}
	switch e.GetExpression().(type) {
	case *Expression_UnaryExpression:
		preOrder(v, e)
		e.GetUnaryExpression().GetExpression().DepthFirstSearch(v)
		postOrder(v, e)
	case *Expression_BinaryExpression:
		preOrder(v, e)
		binaryExpr := e.GetBinaryExpression()
		binaryExpr.GetLeft().DepthFirstSearch(v)
		binaryExpr.GetRight().DepthFirstSearch(v)
		postOrder(v, e)
	case *Expression_NotExpression:
		preOrder(v, e)
		e.GetNotExpression().DepthFirstSearch(v)
		postOrder(v, e)
	case *Expression_AndExpression:
		preOrder(v, e)
		for _, term := range e.GetAndExpression().GetTerms() {
			term.DepthFirstSearch(v)
		}
		postOrder(v, e)
	case *Expression_OrExpression:
		preOrder(v, e)
		for _, term := range e.GetOrExpression().GetTerms() {
			term.DepthFirstSearch(v)
		}
		postOrder(v, e)
	case *Expression_ForInExpression:
		preOrder(v, e)
		forInExpr := e.GetForInExpression()
		forInExpr.GetForExpression().GetExpression().DepthFirstSearch(v)
		integetSet := forInExpr.GetIntegerSet()
		integetSet.GetRange().DepthFirstSearch(v)
		integetSet.GetIntegerEnumeration().DepthFirstSearch(v)
		forInExpr.GetExpression().DepthFirstSearch(v)
		postOrder(v, e)
	case *Expression_ForOfExpression:
		preOrder(v, e)
		forOfExpr := e.GetForOfExpression()
		forOfExpr.GetForExpression().GetExpression().DepthFirstSearch(v)
		forOfExpr.GetExpression().DepthFirstSearch(v)
		postOrder(v, e)
	case *Expression_IntegerFunction:
		preOrder(v, e)
		e.GetIntegerFunction().GetArgument().DepthFirstSearch(v)
		postOrder(v, e)
	case *Expression_Identifier:
		preOrder(v, e)
		for _, item := range e.GetIdentifier().GetItems() {
			item.GetIndex().DepthFirstSearch(v)
			for _, arg := range item.GetArguments().GetTerms() {
				arg.DepthFirstSearch(v)
			}
		}
		postOrder(v, e)
	case *Expression_Range:
		preOrder(v, e)
		e.GetRange().DepthFirstSearch(v)
		postOrder(v, e)
	case *Expression_StringOffset:
		preOrder(v, e)
		e.GetStringOffset().GetIndex().DepthFirstSearch(v)
		postOrder(v, e)
	case *Expression_StringLength:
		preOrder(v, e)
		e.GetStringLength().GetIndex().DepthFirstSearch(v)
		postOrder(v, e)
	default:
		preOrder(v, e)
		postOrder(v, e)
	}
}

// DepthFirstSearch performs a depth-first traversal of the Range's syntax tree,
// it receives a Visitor that must implement PreOrderVisitor, PostOrderVisitor
// or both.
func (r *Range) DepthFirstSearch(v Visitor) {
	if r == nil {
		return
	}
	r.GetStart().DepthFirstSearch(v)
	r.GetEnd().DepthFirstSearch(v)
}

// DepthFirstSearch performs a depth-first traversal of the IntegerEnumeration's
// syntax tree, it receives a Visitor that must implement PreOrderVisitor,
// PostOrderVisitor or both.
func (i *IntegerEnumeration) DepthFirstSearch(v Visitor) {
	if i == nil {
		return
	}
	for _, e := range i.GetValues() {
		e.DepthFirstSearch(v)
	}
}
