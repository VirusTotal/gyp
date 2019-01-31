package yara

import "fmt"

func recoverParse(err *error) {
	if r := recover(); r != nil {
		e := fmt.Errorf("%s", r)
		*err = e
	}
}
