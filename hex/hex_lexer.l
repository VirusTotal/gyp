/*
Copyright (c) 2013. The YARA Authors. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/* Lexical analyzer for hex strings */

%top{
package hex

import (
    "fmt"
    "io"
    "log"
    "os"
    "strconv"

    gyperror "github.com/VirusTotal/gyp/error"
)

type YYcontext struct {}

// YYtype is the structure returned by the lexer every time the scanner asks
// for the next token. If the lexer wants to return an error to the scanner it
// sets the Error field and leaves the Token empty.
type YYtype struct {
  Token int
  Value *hexSymType
  Error gyperror.Error
}

func (s *Scanner) Token(t int) YYtype {
  return YYtype{Token: t}
}

func (s *Scanner) TokenInteger(t int, i int) YYtype {
  return YYtype{Token: t, Value: &hexSymType{integer: i}}
}

func (s *Scanner) TokenByte(t int, value, mask byte) YYtype {
  return YYtype{
    Token: t,
    Value: &hexSymType{
        bm:  byteWithMask{ Mask: byte(mask), Value: byte(value) },
    },
  }
}

func Error(c gyperror.Code, msg string) YYtype {
  return YYtype{Error: gyperror.Error{c, msg, 0,}}
}

}

%{
// Define a constant for end-of-file
const eof = 0
%}

%option reentrant bison-bridge
%option nounput
%option never-interactive
%option yylineno
%option prefix="hex_yy"

%option verbose
%option warn

%x comment
%x yrange

digit         [0-9]
letter        [a-zA-Z]
hexdigit      [a-fA-F0-9]

%%

"{"                     { return yy.Token(_LBRACE_); }
"}"                     { return yy.Token(_RBRACE_); }

<<EOF>> { return yy.Token(eof) }

<INITIAL>{hexdigit}{2}  {
  val, err := strconv.ParseInt(string(yytext), 16, 16)
  if err != nil {
    // This shouldn't happen.
    panic(fmt.Sprintf("error parsing byte: %s\n", err))
  }
  return yy.TokenByte(_BYTE_, byte(val), byte(0xFF));
}

<INITIAL>{hexdigit}\?  {
  yytext[1] = '0'  // Replace ? with 0
  val, err := strconv.ParseInt(string(yytext), 16, 16)
  if err != nil {
    // This shouldn't happen.
    panic(fmt.Sprintf("error parsing byte: %s\n", err))
  }
  return yy.TokenByte(_MASKED_BYTE_, byte(val), byte(0xF0));
}

\?{hexdigit}  {
  yytext[0] = '0'
  val, err := strconv.ParseInt(string(yytext), 16, 16)
  if err != nil {
    // This shouldn't happen.
    panic(fmt.Sprintf("error parsing byte: %s\n", err))
  }
  return yy.TokenByte(_MASKED_BYTE_, byte(val), byte(0x0F));
}

\?\? {
  return yy.TokenByte(_MASKED_BYTE_, byte(0x00), byte(0x00));
}

{hexdigit} {
  return Error(
    gyperror.UnevenNumberOfDigitsError,
    fmt.Sprintf(`uneven number of digits in hex string`))
}

\[ {
  BEGIN (yrange);
  return yy.Token(_LBRACKET_);
}

"/*"(.|\n)*"*/"    // skip comments

"//".*             // skip single-line comments

<yrange>\- {
  return yy.Token(_HYPHEN_);
}

<yrange>{digit}+ {
  val, err := strconv.ParseInt(string(yytext), 10, 32)
  if err != nil {
    // This shouldn't happen.
    panic(fmt.Sprintf("error parsing jump limit: %s\n", err))
  }
  return yy.TokenInteger(_NUMBER_, int(val));
}

<yrange>\] {
  BEGIN (INITIAL);
  return yy.Token(_RBRACKET_);
}

<yrange>[ \t\r\n]   // skip whitespaces

<yrange>. {
  return Error(
    gyperror.InvalidCharInHexStringError,
    fmt.Sprintf(`invalid character in hex string range: %c (0x%02x)`, yytext[0], yytext[0]))
}

[ \t\r\n]         // skip whitespaces

"(" {
  return yy.Token(_LPARENS_)
}

")" {
  return yy.Token(_RPARENS_)
}

"|" {
  return yy.Token(_PIPE_)
}

. {               // reject all other characters
  return Error(
    gyperror.InvalidCharInHexStringError,
    fmt.Sprintf(`invalid character in hex string:  %c (0x%02x)`, yytext[0], yytext[0]))
}

%%
