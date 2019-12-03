package pb

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

func postOrder(v Visitor, e *Expression) {
	if pv, ok := v.(PostOrderVisitor); ok {
		pv.PostOrderVisit(e)
	}
}

func preOrder(v Visitor, e *Expression) {
	if pv, ok := v.(PreOrderVisitor); ok {
		pv.PreOrderVisit(e)
	}
}

// DepthFirstSearch performs a depth-first traversal of the expression's syntax
// tree, it receives a Visitor that must implement PreOrderVisitor, PostOrderVisitor
// or both.
func (e *Expression) DepthFirstSearch(v Visitor) {
	if e == nil {
		return
	}
	preOrder(v, e)
	switch e.GetExpression().(type) {
	case *Expression_UnaryExpression:
		e.GetUnaryExpression().GetExpression().DepthFirstSearch(v)
	case *Expression_BinaryExpression:
		binaryExpr := e.GetBinaryExpression()
		binaryExpr.GetLeft().DepthFirstSearch(v)
		binaryExpr.GetRight().DepthFirstSearch(v)
	case *Expression_NotExpression:
		e.GetNotExpression().DepthFirstSearch(v)
	case *Expression_AndExpression:
		for _, term := range e.GetAndExpression().GetTerms() {
			term.DepthFirstSearch(v)
		}
	case *Expression_OrExpression:
		for _, term := range e.GetOrExpression().GetTerms() {
			term.DepthFirstSearch(v)
		}
	case *Expression_ForInExpression:
		forInExpr := e.GetForInExpression()
		forInExpr.GetForExpression().GetExpression().DepthFirstSearch(v)
		forInExpr.GetIterator().DepthFirstSearch(v)
		forInExpr.GetExpression().DepthFirstSearch(v)
	case *Expression_ForOfExpression:
		forOfExpr := e.GetForOfExpression()
		forOfExpr.GetForExpression().GetExpression().DepthFirstSearch(v)
		forOfExpr.GetExpression().DepthFirstSearch(v)
	case *Expression_IntegerFunction:
		e.GetIntegerFunction().GetArgument().DepthFirstSearch(v)
	case *Expression_Identifier:
		e.GetIdentifier().DepthFirstSearch(v)
	case *Expression_Range:
		e.GetRange().DepthFirstSearch(v)
	case *Expression_StringOffset:
		e.GetStringOffset().GetIndex().DepthFirstSearch(v)
	case *Expression_StringLength:
		e.GetStringLength().GetIndex().DepthFirstSearch(v)
	}
	postOrder(v, e)
}

// DepthFirstSearch performs a depth-first traversal of the Idenfier's syntax
// tree. An identifier may include Expressions for array indexes and function
// arguments, so it can have childs in the syntax tree. It receives a Visitor
// that must implement PreOrderVisitor, PostOrderVisitor or both.
func (i *Identifier) DepthFirstSearch(v Visitor) {
	for _, item := range i.GetItems() {
		item.GetIndex().DepthFirstSearch(v)
		for _, arg := range item.GetArguments().GetTerms() {
			arg.DepthFirstSearch(v)
		}
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

// DepthFirstSearch performs a depth-first traversal of the IntegerSet's
// syntax tree, it receives a Visitor that must implement PreOrderVisitor,
// PostOrderVisitor or both.
func (i *IntegerSet) DepthFirstSearch(v Visitor) {
	if i == nil {
		return
	}
	switch i.GetSet().(type) {
	case *IntegerSet_IntegerEnumeration:
		i.GetIntegerEnumeration().DepthFirstSearch(v)
	case *IntegerSet_Range:
		i.GetRange().DepthFirstSearch(v)
	}
}

// DepthFirstSearch performs a depth-first traversal of the Iterators's
// syntax tree, it receives a Visitor that must implement PreOrderVisitor,
// PostOrderVisitor or both.
func (i *Iterator) DepthFirstSearch(v Visitor) {
	if i == nil {
		return
	}
	switch i.GetIterator().(type) {
	case *Iterator_IntegerSet:
		i.GetIntegerSet().DepthFirstSearch(v)
	case *Iterator_Identifier:
		i.GetIdentifier().DepthFirstSearch(v)
	}
}
