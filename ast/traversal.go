package ast

// Visitor is the interface that must be implemented for getting notified about
// nodes visited during ast tree traversal.
type Visitor interface{}

// PreOrderVisitor is the interface that must be implemented by a visitor that
// wants to be notified about expressions before any of the expression's sub
// expressions is visited.
type PreOrderVisitor interface {
	Visitor
	PreOrderVisit(Node)
}

// PostOrderVisitor is the interface that must be implemented by a visitor that
// wants to be notified about expressions after all of the expression's sub
// expressions are visited.
type PostOrderVisitor interface {
	Visitor
	PostOrderVisit(Node)
}

func postOrder(v Visitor, n Node) {
	if pv, ok := v.(PostOrderVisitor); ok {
		pv.PostOrderVisit(n)
	}
}

func preOrder(v Visitor, n Node) {
	if pv, ok := v.(PreOrderVisitor); ok {
		pv.PreOrderVisit(n)
	}
}

// DepthFirstSearch performs a depth-first traversal of the given node's syntax
// tree. It receives a Visitor that must implement PreOrderVisitor,
// PostOrderVisitor or both.
func DepthFirstSearch(node Node, v Visitor) {
	preOrder(v, node)

	for _, n := range node.Children() {
		DepthFirstSearch(n, v)
	}

	postOrder(v, node)
}
