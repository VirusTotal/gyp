all: grammar y2j

grammar:
	flexgo -G -v -o grammar/lexer.go grammar/lexer.l && goyacc -p xx -o grammar/parser.go grammar/grammar.y

proto:
	cd data && protoc --go_out=. data.proto

j2y:
	go build github.com/VirusTotal/go-yara-parser/cmd/j2y

y2j:
	go build github.com/VirusTotal/go-yara-parser/cmd/y2j

release: parser lexer
	GOOS=linux go build -o y2j-linux github.com/VirusTotal/go-yara-parser/cmd/y2j
	GOOS=darwin go build -o y2j-mac github.com/VirusTotal/go-yara-parser/cmd/y2j
	GOOS=windows go build -o y2j.exe github.com/VirusTotal/go-yara-parser/cmd/y2j

clean:
	rm grammar/lexer.go grammar/parser.go data/data.pb.go y.output y2j
