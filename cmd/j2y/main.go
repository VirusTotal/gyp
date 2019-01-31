package main

import (
	jsonpb "github.com/golang/protobuf/jsonpb"
	"io"
	"os"

	"github.com/VirusTotal/go-yara-parser/data"
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

	var ruleset data.RuleSet
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

	serializer := data.YaraSerializer{Indent: opts.Indent}
	txt, err := serializer.Serialize(ruleset)
	if err != nil {
		perror(`Couldn't serialize ruleset: %s`, err)
		os.Exit(6)
	}

	_, err = out.Write([]byte(txt))
	if err != nil {
		perror(`Error writing YARA: %s`, err)
		os.Exit(6)
	}
}
