all: grammar y2j

grammar:
	flexgo -G -v -o lexer.go lexer.l && goyacc -p xx -o parser.go grammar.y

proto:
	protoc --go_out=. yara.proto

j2y:
	go build github.com/VirusTotal/go-yara-parser/cmd/j2y

y2j:
	go build github.com/VirusTotal/go-yara-parser/cmd/y2j

release: parser lexer
	GOOS=linux go build -o y2j-linux github.com/VirusTotal/go-yara-parser/cmd/y2j
	GOOS=darwin go build -o y2j-mac github.com/VirusTotal/go-yara-parser/cmd/y2j
	GOOS=windows go build -o y2j.exe github.com/VirusTotal/go-yara-parser/cmd/y2j

clean:
	rm lexer.go parser.go yara.pb.go y.output y2j j2y
