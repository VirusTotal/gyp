all: proto grammar y2j

grammar:
	flexgo -G -v -o parser/lexer.go parser/lexer.l && goyacc -p yr -o parser/parser.go parser/grammar.y

hexgrammar:
	flexgo -G -v -o hex/hex_lexer.go hex/hex_lexer.l && goyacc -p xx -o hex/hex_parser.go hex/hex_grammar.y

proto:
	protoc --go_out=. pb/yara.proto

j2y:
	go build github.com/VirusTotal/gyp/cmd/j2y

y2j:
	go build github.com/VirusTotal/gyp/cmd/y2j

release: parser lexer
	GOOS=linux go build -o y2j-linux github.com/VirusTotal/gyp/cmd/y2j
	GOOS=darwin go build -o y2j-mac github.com/VirusTotal/gyp/cmd/y2j
	GOOS=windows go build -o y2j.exe github.com/VirusTotal/gyp/cmd/y2j

clean:
	rm parser/lexer.go parser/parser.go pb/yara.pb.go y.output y2j j2y
