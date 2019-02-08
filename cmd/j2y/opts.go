package main

import (
	"flag"
	"os"
	"strings"
)

type options struct {
	Indent  string
	Infile  string
	Outfile string
}

func getopt() options {
	var (
		o      options
		indent int
	)

	flag.IntVar(&indent, "indent", 2, "Set number of indent spaces")
	flag.StringVar(&o.Outfile, "o", "", "YARA output file")

	flag.Parse()

	// Set indent
	o.Indent = strings.Repeat(" ", indent)

	// The JSON file is the only positional argument
	if n := flag.NArg(); n != 1 {
		perror("Expected 1 input file; found %d", n)
		os.Exit(1)
	}

	o.Infile = flag.Args()[0]

	return o
}
