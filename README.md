# go-yara-parser

`go-yara-parser` is a Go library for manipulating YARA rulesets.
It uses the same grammar and lexer files as the original libyara to ensure that lexing and parsing work exactly like YARA.
The grammar and lexer files have been modified to fill protocol buffers (PB) messages for ruleset manipulation instead of compiling rulesets for data matching.

Using `go-yara-parser`, one will be able to read YARA rulesets to programatically change metadata, rule names, rule modifiers, tags, strings, conditions and more.

Encoding rulesets as PB messages enable their manipulation in other languages.
Additionally, the `y2j` tool is provided for serializing rulesets to JSON.
Similarly, `j2y` provides JSON-to-YARA conversion, but do see __Limitations__ below.

## `y2j` Usage

Command line usage for `y2j` looks like the following:

```
$ y2j --help            
Usage of y2j: y2j [options] file.yar

options:
  -indent int
        Set number of indent spaces (default 2)
  -o string               
        JSON output file
```

In action, `y2j` would convert the following ruleset:

```yara
import "pe"
import "cuckoo"

include "other.yar"

global rule demo : tag1 {
meta:
    description = "This is a demo rule"
    version = 1
    production = false
    description = "because we can"
strings:
    $string = "this is a string" nocase wide
    $regex = /this is a regex/i ascii fullword
    $hex = { 01 23 45 67 89 ab cd ef [0-5] ?1 ?2 ?3 }
condition:
    $string or $regex or $hex
}
```

to this JSON output:

```json
{
  "file": "sample.yar",
  "imports": [
    "pe",
    "cuckoo"
  ],
  "includes": [
    "other.yar"
  ],
  "rules": [
    {
      "modifiers": {
        "global": true,
        "private": false
      },
      "identifier": "demo",
      "tags": [
        "tag1"
      ],
      "meta": [
        {
          "key": "description",
          "val": "This is a demo rule"
        },
        {
          "key": "version",
          "val": 1
        },
        {
          "key": "production",
          "val": false
        },
        {
          "key": "description",
          "val": "because we can"
        }
      ],
      "strings": [
        {
          "id": "$string",
          "type": "TEXT",
          "text": "this is a string",
          "modifiers": {
            "nocase": true,
            "ascii": false,
            "wide": true,
            "fullword": false,
            "xor": false
          }
        },
        {
          "id": "$regex",
          "type": "REGEX",
          "text": "this is a regex",
          "modifiers": {
            "nocase": false,
            "ascii": true,
            "wide": false,
            "fullword": true,
            "xor": false,
            "i": true
          }
        },
        {
          "id": "$hex",
          "type": "HEX",
          "text": "01 23 45 67 89 ab cd ef [0-5] ?1 ?2 ?3"
        }
      ],
      "condition": {
        "orExpression": {
          "terms": [
            {
              "stringIdentifier": "$string"
            },
            {
              "stringIdentifier": "$regex"
            },
            {
              "stringIdentifier": "$hex"
            }
          ]
        }
      }
    }
  ]
}
```

## Go Usage

Sample usage for working with rulesets in Go looks like the following:

```go
package main

import (
  "fmt"
  "log"
  "os"
  proto "github.com/golang/protobuf/proto"

  "github.com/VirusTotal/go-yara-parser/grammar"
)

func main() {
  input, err := os.Open(os.Args[1])   // Single argument: path to your file
  if err != nil {
    log.Fatalf("Error: %s\n", err)
  }

  ruleset, err := grammar.Parse(input, os.Stdout)
  if err != nil {
    log.Fatalf(`Parsing failed: "%s"`, err)
  }

  fmt.Printf("Ruleset:\n%v\n", ruleset)

  // Manipulate the first rule
  rule := ruleset.Rules[0]
  rule.Identifier = proto.String("new_rule_name")
  rule.Modifiers.Global = proto.Bool(true)
  rule.Modifiers.Private = proto.Bool(false)
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

- Build parser and lexer: `make grammar`
- Build data protocol buffer: `make proto`
- Build `y2j` tool: `make y2j`
- Build `j2y` tool: `make j2y`

## Limitations

Currently, there are no guarantees with the library that modified rules will serialize back into a valid YARA ruleset:

1. you can set `rule.Identifier = "123"`, but this would be invalid YARA.
2. Adding or removing strings may cause a condition to become invalid.
3. Comments cannot be retained.
4. Numbers are always serialized in decimal base.

## License and third party code

This project uses code from [`yara-parser`](https://github.com/Northern-Lights/yara-parser) by [Northern-Lights](https://github.com/Northern-Lights), which is available under the MIT license (see `LICENSES_THIRD_PARTIES`).
