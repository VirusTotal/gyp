FLEXGO ?= flexgo
GOYACC ?= goyacc
PROTOC ?= protoc-gen-go

all: proto hexgrammar grammar y2j j2y

grammar:
	${FLEXGO} -G -v -o parser/lexer.go parser/lexer.l && ${GOYACC} -p yr -o parser/parser.go parser/grammar.y

hexgrammar:
	${FLEXGO} -G -v -o hex/hex_lexer.go hex/hex_lexer.l && ${GOYACC} -p hex -o hex/hex_parser.go hex/hex_grammar.y

proto:
	protoc --plugin=${PROTOC} --go_out=. --go_opt=paths=source_relative pb/yara.proto

j2y:
	go build github.com/VirusTotal/gyp/cmd/j2y

y2j:
	go build github.com/VirusTotal/gyp/cmd/y2j

release:
	GOOS=linux go build -o y2j-linux github.com/VirusTotal/gyp/cmd/y2j
	GOOS=darwin go build -o y2j-mac github.com/VirusTotal/gyp/cmd/y2j
	GOOS=windows go build -o y2j.exe github.com/VirusTotal/gyp/cmd/y2j

clean:
	rm parser/lexer.go parser/parser.go pb/yara.pb.go y.output y2j j2y
