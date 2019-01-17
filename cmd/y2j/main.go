package main

import (
	"encoding/json"
	"io"
	"os"

	"github.com/VirusTotal/go-yara-parser/grammar"
)

// global options
var opts options

func main() {
	opts = getopt()

	yaraFile, err := os.Open(opts.Infile)
	if err != nil {
		perror(`Couldn't open YARA file "%s": %s`, opts.Infile, err)
		os.Exit(2)
	}
	defer handleErr(yaraFile.Close)

	ruleset, err := grammar.Parse(yaraFile, os.Stdout)
	if err != nil {
		perror(`Couldn't parse YARA ruleset: %s`, err)
		os.Exit(3)
	}
	ruleset.File = opts.Infile

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

	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", opts.Indent)
	err = enc.Encode(&ruleset)
	if err != nil {
		perror(`Error writing JSON: %s`, err)
		os.Exit(6)
	}
}
