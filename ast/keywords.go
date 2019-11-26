package ast

import (
	"fmt"
	"io"

	"github.com/VirusTotal/gyp/pb"
	"github.com/golang/protobuf/proto"
)

// Keyword is a Node that represents a keyword.
type Keyword string

// Constants for existing keywords.
const (
	KeywordAll        Keyword = "all"
	KeywordAny        Keyword = "any"
	KeywordEntrypoint Keyword = "entrypoint"
	KeywordFalse      Keyword = "false"
	KeywordFilesize   Keyword = "filesize"
	KeywordThem       Keyword = "them"
	KeywordTrue       Keyword = "true"
)

// WriteSource writes the keyword into the writer w.
func (k Keyword) WriteSource(w io.Writer) error {
	_, err := io.WriteString(w, string(k))
	return err
}

// Children returns an empty list of nodes as a keyword never has children,
// this function is required anyways in order to satisfy the Node interface.
func (k Keyword) Children() []Node {
	return []Node{}
}

// AsProto returns the keyword serialized as a protobuf.
func (k Keyword) AsProto() proto.Message {
	switch k {
	case KeywordTrue:
		return &pb.Expression{
			Expression: &pb.Expression_BoolValue{
				BoolValue: true,
			}}
	case KeywordFalse:
		return &pb.Expression{
			Expression: &pb.Expression_BoolValue{
				BoolValue: false,
			}}
	case KeywordEntrypoint:
		return &pb.Expression{
			Expression: &pb.Expression_Keyword{
				Keyword: pb.Keyword_ENTRYPOINT,
			}}
	case KeywordFilesize:
		return &pb.Expression{
			Expression: &pb.Expression_Keyword{
				Keyword: pb.Keyword_FILESIZE,
			}}
	default:
		panic(fmt.Sprintf(`unexpected keyword "%s"`, k))
	}
}
