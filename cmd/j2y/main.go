package main

import (
	jsonpb "github.com/golang/protobuf/jsonpb"
	"io"
	"os"

	"github.com/VirusTotal/gyp"
	"github.com/VirusTotal/gyp/ast"
)

// global options
var opts options

func main() {
	opts = getopt()

	jsonFile, err := os.Open(opts.Infile)
	if err != nil {
		perror(`Couldn't open JSON file "%s": %s`, opts.Infile, err)
		os.Exit(2)
	}
	defer handleErr(jsonFile.Close)

	var ruleset ast.RuleSet
	unmarshaler := jsonpb.Unmarshaler{}
	err = unmarshaler.Unmarshal(jsonFile, &ruleset)

	if err != nil {
		perror(`Couldn't JSON decode file: %s`, err)
		os.Exit(3)
	}

	// Set output to stdout if not specified; otherwise file
	var out io.Writer
	if opts.Outfile == "" {
		out = os.Stdout
	} else {
		f, err := os.Create(opts.Outfile)
		if err != nil {
			perror(`Couldn't create output file "%s"`, opts.Outfile)
			os.Exit(5)
		}
		defer handleErr(f.Close)
		out = f
	}

	serializer := gyp.NewSerializer(out)
	serializer.SetIndent(opts.Indent)
	if err := serializer.Serialize(&ruleset); err != nil {
		perror(`Couldn't serialize ruleset: %s`, err)
		os.Exit(6)
	}
}
