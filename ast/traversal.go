package ast

// searchCallback is the kind of function passed to DepthFirstSearch to get
// notified about the traversed nodes in a gyp ast tree.
type searchCallback func(expr Node, cbParam interface{})

// DepthFirstSearch performs a depth-first traversal of expr's syntax tree and
// invokes callback with the given cbParam for every node found.
func DepthFirstSearch(expr Node, callback searchCallback, cbParam interface{}) {
	callback(expr, cbParam)
	for _, expr := range expr.Children() {
		DepthFirstSearch(expr, callback, cbParam)
	}
}
