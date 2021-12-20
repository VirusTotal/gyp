/*
Copyright (c) 2007-2013. The YARA Authors. All Rights Reserved.

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

/* Lexical analyzer for YARA */

%top{
package parser

import (
    "fmt"
    "io"
    "log"
    "os"
    "math"
    "strconv"
    "strings"
    "unicode/utf8"

    "github.com/VirusTotal/gyp/ast"
    "github.com/VirusTotal/gyp/hex"
    gyperror "github.com/VirusTotal/gyp/error"
)

type YYcontext struct {}

// YYtype is the structure returned by the lexer every time the scanner asks
// for the next token. Each token may have an associated value, for example,
// the _IDENTIFIER_ token has an associated string with the identifier's name.
// If the lexer wants to return an error to the scanner it
// sets the Error field and leaves the Token and Value empty.
type YYtype struct {
  Token int
  Lineno int
  Value *yrSymType
  Error gyperror.Error
}

// Token creates a YYtype struct for the given token type with no associated
// value.
func (s *Scanner) Token(t int) YYtype {
  return YYtype{Token: t, Lineno: s.Lineno}
}

// TokenString creates a YYtype struct for the given token type with an
// associated string.
func (s *Scanner) TokenString(t int, v string) YYtype {
  return YYtype{Token: t, Lineno: s.Lineno, Value: &yrSymType{s: v}}
}

func (s *Scanner) TokenInt64(t int, v int64) YYtype {
  return YYtype{Token: t, Lineno: s.Lineno, Value: &yrSymType{i64: v}}
}

func (s *Scanner) TokenFloat64(t int, v float64) YYtype {
  return YYtype{Token: t, Lineno: s.Lineno, Value: &yrSymType{f64: v}}
}

func (s *Scanner) TokenRegExp(reg *ast.LiteralRegexp) YYtype {
  return YYtype{Token: _REGEXP_, Lineno: s.Lineno, Value: &yrSymType{reg: reg}}
}

func (s *Scanner) TokenHexString(hexTokens []ast.HexToken) YYtype {
  return YYtype{Token: _HEX_STRING_, Lineno: s.Lineno, Value: &yrSymType{hexTokens: hexTokens}}
}

func Error(c gyperror.Code, msg string) YYtype {
  return YYtype{Error: gyperror.Error{c, msg, 0,}}
}

func validateAscii(s string) error {
  for i := 0; i < len(s); i++ {
    if s[i] < 32 || s[i] >= 127 {
       return fmt.Errorf(`invalid ASCII character "\x%02x"`, s[i])
    }
  }
  return nil
}

func validateUTF8(s string) error {
  for index, rune := range s {
    if rune == utf8.RuneError {
        return fmt.Errorf(`invalid UTF-8 character "\x%02x"`, s[index])
    }
  }
  return nil
}

// The YY_USER_DATA macro is used to define variables inside the Scanner
// Lex() method. These variables manage buffers for gathering groups of
// tokens. Flex collects tokens individually but strings and conditions may
// contain several tokens.
// Two different buffers are necessary because conditions may contain strings.

// This comment applies to the YY_USER_ACTION macro, which is having
// a problem with comments...
// For condition, the colons and whitespace will be collected in the
// prefix and the right brace for the suffix. Use strings.TrimLeft/Right
}

%{
YY_USER_DATA(
  var (
    str      []byte
    regexp   []byte
    YYtext   string  // each action sets this to the current yytext
  )
)

YY_USER_ACTION(
  YYtext = string(yytext)
)

// Define a constant for end-of-file
const eof = 0
%}

%option reentrant bison-bridge
%option nounput
%option never-interactive
%option yylineno
%option prefix="yara_yy"

%option verbose
%option warn

%x STR
%x REGEXP
%x COMMENT

digit         [0-9]
letter        [a-zA-Z]
hexdigit      [a-fA-F0-9]
octdigit      [0-7]

%%

".."                    { return yy.Token(_DOT_DOT_);     }
"<"                     { return yy.Token(_LT_);          }
">"                     { return yy.Token(_GT_);          }
"<="                    { return yy.Token(_LE_);          }
">="                    { return yy.Token(_GE_);          }
"=="                    { return yy.Token(_EQ_);          }
"!="                    { return yy.Token(_NEQ_);         }
"<<"                    { return yy.Token(_SHIFT_LEFT_);  }
">>"                    { return yy.Token(_SHIFT_RIGHT_); }
"private"               { return yy.Token(_PRIVATE_);     }
"global"                { return yy.Token(_GLOBAL_);      }
"rule"                  { return yy.Token(_RULE_);        }
"meta"                  { return yy.Token(_META_);        }
"strings"               { return yy.Token(_STRINGS_);     }
"ascii"                 { return yy.Token(_ASCII_);       }
"base64"                { return yy.Token(_BASE64_);      }
"base64wide"            { return yy.Token(_BASE64WIDE_);  }
"wide"                  { return yy.Token(_WIDE_);        }
"xor"                   { return yy.Token(_XOR_);         }
"fullword"              { return yy.Token(_FULLWORD_);    }
"nocase"                { return yy.Token(_NOCASE_);      }
"condition"             { return yy.Token(_CONDITION_);   }
"true"                  { return yy.Token(_TRUE_);        }
"false"                 { return yy.Token(_FALSE_);       }
"not"                   { return yy.Token(_NOT_);         }
"and"                   { return yy.Token(_AND_);         }
"or"                    { return yy.Token(_OR_);          }
"at"                    { return yy.Token(_AT_);          }
"in"                    { return yy.Token(_IN_);          }
"of"                    { return yy.Token(_OF_);          }
"them"                  { return yy.Token(_THEM_);        }
"for"                   { return yy.Token(_FOR_);         }
"all"                   { return yy.Token(_ALL_);         }
"any"                   { return yy.Token(_ANY_);         }
"none"                  { return yy.Token(_NONE_);        }
"entrypoint"            { return yy.Token(_ENTRYPOINT_);  }
"filesize"              { return yy.Token(_FILESIZE_);    }
"matches"               { return yy.Token(_MATCHES_);     }
"contains"              { return yy.Token(_CONTAINS_);    }
"icontains"             { return yy.Token(_ICONTAINS_);   }
"startswith"            { return yy.Token(_STARTSWITH_);  }
"istartswith"           { return yy.Token(_ISTARTSWITH_); }
"endswith"              { return yy.Token(_ENDSWITH_);    }
"iendswith"             { return yy.Token(_IENDSWITH_);   }
"import"                { return yy.Token(_IMPORT_);      }
"include"               { return yy.Token(_INCLUDE_);     }

"/*"                    { BEGIN (COMMENT);       }
<COMMENT>"*/"           { BEGIN (INITIAL);       }
<COMMENT>(.|\n)         { /* skip comments */   }


"//"[^\n]*              { /* skip single-line comments */ }

<<EOF>> { return yy.Token(eof) }


$({letter}|{digit}|_)*"*"  {
  return yy.TokenString(_STRING_IDENTIFIER_WITH_WILDCARD_, string(yytext));
}


$({letter}|{digit}|_)*  {
  return yy.TokenString(_STRING_IDENTIFIER_, string(yytext));
}


#({letter}|{digit}|_)*  {
  return yy.TokenString(_STRING_COUNT_, string(yytext));
}


@({letter}|{digit}|_)*  {
  return yy.TokenString(_STRING_OFFSET_, string(yytext));
}


!({letter}|{digit}|_)*  {
  return yy.TokenString(_STRING_LENGTH_, string(yytext));
}


u?int(8|16|32)(be)? {
  return yy.TokenString(_INTEGER_FUNCTION_, string(yytext));
}


({letter}|_)({letter}|{digit}|_)*"*"  {
  return yy.TokenString(_IDENTIFIER_WITH_WILDCARD_, string(yytext));
}


({letter}|_)({letter}|{digit}|_)*  {
  return yy.TokenString(_IDENTIFIER_, string(yytext));
}


{digit}+(MB|KB){0,1}  {
  s := strings.TrimRight(YYtext, "MKB")
  v, err := strconv.ParseInt(s, 10, 64)
  if err != nil {
    return Error(
      gyperror.NumberConversionError,
      fmt.Sprintf("%s", err))
  }
  if strings.HasSuffix(YYtext, "KB") {
      if v > math.MaxInt64 / 1024 {
        return Error(
          gyperror.IntegerOverflowError,
          fmt.Sprintf("Found %s; Max: %d", YYtext, int64(math.MaxInt64)))
      } else {
        v *= 1024
      }
  } else if strings.HasSuffix(YYtext, "MB") {
      if v > math.MaxInt64 / 1048576 {
        return Error(
          gyperror.IntegerOverflowError,
          fmt.Sprintf("Found %s; Max: %d", YYtext, int64(math.MaxInt64)))
      } else {
          v *= 1048576
      }
  }
  return yy.TokenInt64(_NUMBER_, v);
}

{digit}+"."{digit}+  {
  v, err := strconv.ParseFloat(YYtext, 64)
  if err != nil {
    return Error(
      gyperror.NumberConversionError,
      fmt.Sprintf("%s", err))
  }
  return yy.TokenFloat64(_DOUBLE_, v);
}

0x{hexdigit}+  {
  v, err := strconv.ParseInt(YYtext, 0, 64)
  if err != nil {
    return Error(
      gyperror.NumberConversionError,
      fmt.Sprintf("%s", err))
  }
  return yy.TokenInt64(_NUMBER_, v);
}

0o{octdigit}+  {
  s := strings.TrimLeft(YYtext, "0o")
  v, err := strconv.ParseInt(s, 8, 64)
  if err != nil {
    return Error(
      gyperror.NumberConversionError,
      fmt.Sprintf("%s", err))
  }
  return yy.TokenInt64(_NUMBER_, v);
}


<STR>\"   {     /* saw closing quote - all done */
  BEGIN (INITIAL);
  return yy.TokenString(_TEXT_STRING_, string(str));
}


<STR>\\t   {
  str = append(str, yytext...)
}


<STR>\\r   {
  str = append(str, yytext...)
}


<STR>\\n   {
  str = append(str, yytext...)
}


<STR>\\\"   {
  str = append(str, yytext...)
}


<STR>\\\\  {
  str = append(str, yytext...)
}


<STR>\\x{hexdigit}{2} {
  str = append(str, yytext...)
}


<STR>[^\\\n\"]+   {
  str = append(str, yytext...)
}


<STR>\n  {
  return Error(
    gyperror.UnterminatedStringError,
    "unterminate string")
}


<STR>\\(.|\n) {
  return Error(
    gyperror.IllegalEscapeSequenceError,
    "illegal escape sequence")
}


<REGEXP>\/i?s?  {
  if err := validateUTF8(string(regexp)); err != nil {
    return Error(gyperror.InvalidUTF8Error, err.Error())
  }

  var mods ast.RegexpModifiers
  for _, c := range YYtext {
      switch c {
      case 'i':
          mods = mods | ast.RegexpCaseInsensitive
      case 's':
          mods = mods | ast.RegexpDotAll
      case '/':
          // Ignore
      default:
          // Should be impossible
          return Error(
            gyperror.InvalidRegexModifierError,
            fmt.Sprintf(`invalid regexp modifier "%c"`, c))
      }
  }

  BEGIN (INITIAL);
  return yy.TokenRegExp(&ast.LiteralRegexp{
     Value: string(regexp),
     Modifiers: mods,
  });
}


<REGEXP>\\\/  {
  regexp = append(regexp, yytext...)
}


<REGEXP>\\. {
  regexp = append(regexp, yytext...)
}


<REGEXP>[^/\n\\]+ {
  regexp = append(regexp, yytext...)
}


<REGEXP>\n  {
  return Error(
    gyperror.UnterminatedRegexError,
    "unterminated regexp")
}


\"  {
  str = []byte{}
  BEGIN (STR);
}


"/"  {
  regexp = []byte{}
  BEGIN (REGEXP);
}


\{(({hexdigit}|[ \-|\?\[\]\(\)\n\r\t]|\/\*[^*]*\*\/)+|\/\/.*)+\}  {
  // Match hex-digits with whitespace or comments. The latter are stripped
  // out by hex_lexer.l

  // NOTE: The above comment may not apply. We plan to not use hex_lexer.l

  // No need to collect like str and regexp start conditions
  hexTokens, err := hex.Parse(strings.NewReader(YYtext))
  if err != nil {
    return YYtype{Error: err.(gyperror.Error)}
  }

  return yy.TokenHexString(hexTokens);
}


[ \t\r\n]   /* skip whitespace */

.   {

  r := int(yytext[0])

  if r >= 32 && r < 127 {
    return yy.Token(r)
  }

  return Error(
    gyperror.InvalidAsciiError,
    fmt.Sprintf(`invalid ASCII character "\x%02x"`, r))
}

%%
