package main

import (
	"fmt"
	"os"
	"strings"
)

// perror writes a format string and args to stderr
func perror(s string, a ...interface{}) {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(s, a...))
	sb.WriteRune('\n')
	os.Stderr.WriteString(sb.String())
}

// handleErr should be deferred to report any errors in deferred functions
func handleErr(f func() error) {
	err := f()
	if err != nil {
		perror(`Error: %s`, err)
		os.Exit(127)
	}
}
