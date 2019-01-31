package tests

import (
	"io"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/VirusTotal/go-yara-parser/data"
	"github.com/VirusTotal/go-yara-parser/grammar"
)

const testFile = "ruleset.yar"

var ruleset data.RuleSet
var inputYaraRuleset string

func init() {
	f, err := os.Open(testFile)
	if err != nil {
		log.Fatalf(`Unable to open ruleset file "%s": %s`, testFile, err)
	}
	ruleset, err = grammar.Parse(f, os.Stderr)
	if err != nil {
		log.Fatalf(`Unable to parse ruleset file "%s": %s`, testFile, err)
	}

	_, err = f.Seek(0, 0)
	if err != nil {
		log.Fatalf(`Unable to seek start of ruleset file "%s": %s`, testFile, err)
	}

	buffer := make([]byte, 100)
	read, err := f.Read(buffer)
	var b strings.Builder
	for ; err == nil; read, err = f.Read(buffer) {
		b.Write(buffer[:read])
	}

	if err != io.EOF {
		log.Fatalf(`Error reading ruleset file "%s": %s`, testFile, err)
	}

	inputYaraRuleset = b.String()
}

func TestRulesetParsing(t *testing.T) {
	serializer := data.YaraSerializer{Indent: "  "}
	yaraRules, err := serializer.Serialize(ruleset)
	if err != nil {
		log.Fatalf(`Unable to serialize ruleset to YARA: %s`, err)
	}

	if yaraRules != inputYaraRuleset {
		log.Fatalf(
			"Generated YARA ruleset does not match input file.\nOutput:\n%s",
			yaraRules,
		)
	}
}
