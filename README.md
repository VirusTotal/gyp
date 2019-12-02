[![GoDoc](https://godoc.org/github.com/VirusTotal/gyp?status.svg)](https://godoc.org/github.com/VirusTotal/gyp)
[![Go Report Card](https://goreportcard.com/badge/github.com/VirusTotal/gyp)](https://goreportcard.com/report/github.com/VirusTotal/gyp)

# gyp (go-yara-parser)

`gyp` is a Go library for parsing YARA rules. It uses the same grammar and lexer files as the original libyara to ensure that lexing and parsing work exactly like YARA. This library produces an Abstract Syntax Tree (AST) for the parsed YARA rules. Additionally, the AST can be serialized as a Protocol Buffer, which facilitate its manipulation in other programming languages.

## Go Usage

The example below illustrates the usage of `gyp`, this a simple program that reads a YARA source file from the standard input, creates the corresponding AST, and writes the rules back to the standard output. The resulting output won't be exactly like the input, during the parsing and re-generation of the rules the text is reformatted and comments are lost.

```go
package main

import (
	"log"
	"os"

	"github.com/VirusTotal/gyp"
)

func main() {
	ruleset, err := gyp.Parse(os.Stdin)
	if err != nil {
		log.Fatalf(`Error parsing rules: %v`, err)
	}
	if err = ruleset.WriteSource(os.Stdout); err != nil {
		log.Fatalf(`Error writing rules: %v`, err)
	}
}
```

## Development

### Setup development environment (Linux)

1. Install the required packages using your package manager (`apt` is assumed in the following example):
```bash
	apt update && apt install \
		automake \
		bison \
		help2man \
		m4 \
		texinfo \
		texlive
```
2. Install golang following the provided [installation instructions](https://golang.org/doc/install).
3. Install golang protobuf package following the provided [installation instructions](https://github.com/golang/protobuf).
4. Install the project dependencies:
  - `go get golang.org/x/tools/cmd/goyacc`
  - `go get github.com/pebbe/flexgo/...`
  - Add the environment variable `FLEXGO`, pointing out to the flexgo folder in your Go workspace (e.g., `$HOME/go/src/github.com/pebbe/flexgo`).
  - `cd ${FLEXGO} && ./configure && cd -`
  - `make -C ${FLEXGO} && make -C ${FLEXGO} install`

### Build project

The `Makefile` includes targets for quickly building the parser and lexer and the data protocol buffer, as well as the `y2j` and `j2y` command-line tools:

- Build rulesets parser and lexer: `make grammar`
- Build hex strings parser and lexer: `make hexgrammar`
- Build ruleset protocol buffer: `make proto`
- Build `y2j` tool: `make y2j`
- Build `j2y` tool: `make j2y`


## License and third party code

This project uses code from [`yara-parser`](https://github.com/Northern-Lights/yara-parser) by [Northern-Lights](https://github.com/Northern-Lights), which is available under the MIT license (see `LICENSES_THIRD_PARTIES`).
