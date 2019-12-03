package ast

import (
	"fmt"
	"io"
	"strings"
	"text/template"

	"github.com/VirusTotal/gyp/pb"
	"github.com/golang/protobuf/proto"
)

// Rule describes a YARA rule.
type Rule struct {
	Global     bool
	Private    bool
	Identifier string
	Tags       []string
	Meta       []*Meta
	Strings    []String
	Condition  Expression
}

// RuleSet describes a set of YARA rules.
type RuleSet struct {
	Imports  []string
	Includes []string
	Rules    []*Rule
}

var ruleTmpl = template.Must(template.New("rule").Parse(`
{{ with .Rule -}}
{{ if .Global }}global {{ end -}}
{{ if .Private }}private {{ end -}}
rule {{ .Identifier }} {{ if .Tags }}: {{ range .Tags }}{{ . }} {{ end }}{{ end }}{
{{- if .Meta }}
  meta:
  {{- range .Meta }}
    {{ . }}
  {{- end }}
{{- end }}
{{- if .Strings }}
  strings:
  {{- range .Strings }}
    {{ . }}
  {{- end }}
{{- end }}
{{- end }}
  condition:
    {{ .Condition }}
}`))

// WriteSource writes the rule's source into the writer w.
func (r *Rule) WriteSource(w io.Writer) error {
	if r.Condition == nil {
		panic("rule without condition")
	}
	var condition strings.Builder
	if err := r.Condition.WriteSource(&condition); err != nil {
		return err
	}
	t := struct {
		Rule      *Rule
		Condition string
	}{
		Rule:      r,
		Condition: condition.String(),
	}
	return ruleTmpl.Execute(w, t)
}

// WriteSource writes the ruleset's source into the writer w.
func (r *RuleSet) WriteSource(w io.Writer) error {
	for _, include := range r.Includes {
		if _, err := fmt.Fprintf(w, `include "%s"`, include); err != nil {
			return err
		}
	}
	for _, r := range r.Rules {
		if err := r.WriteSource(w); err != nil {
			return err
		}
	}
	return nil
}

// Children returns the node's children.
func (r *Rule) Children() []Node {
	return []Node{r.Condition}
}

// AsProto returns the rule serialized as a Rule protobuf message.
func (r *Rule) AsProto() *pb.Rule {
	meta := make([]*pb.Meta, len(r.Meta))
	for i, m := range r.Meta {
		meta[i] = m.AsProto()
	}
	strings := make([]*pb.String, len(r.Strings))
	for i, s := range r.Strings {
		strings[i] = s.AsProto()
	}
	return &pb.Rule{
		Modifiers: &pb.RuleModifiers{
			Global:  proto.Bool(r.Global),
			Private: proto.Bool(r.Private),
		},
		Identifier: proto.String(r.Identifier),
		Tags:       r.Tags,
		Meta:       meta,
		Strings:    strings,
		Condition:  r.Condition.AsProto(),
	}
}

// AsProto returns the rule set serialized as the RuleSet protobuf message.
func (r *RuleSet) AsProto() *pb.RuleSet {
	rules := make([]*pb.Rule, len(r.Rules))
	for i, rule := range r.Rules {
		rules[i] = rule.AsProto()
	}
	return &pb.RuleSet{
		Imports:  r.Imports,
		Includes: r.Includes,
		Rules:    rules,
	}
}
