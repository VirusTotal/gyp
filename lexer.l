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
package yara

import (
    "fmt"
    "io"
    "log"
    "os"
    "math"
    "strconv"
    "strings"
    proto "github.com/golang/protobuf/proto"

    "github.com/VirusTotal/go-yara-parser/data"
    "github.com/VirusTotal/go-yara-parser/hex"
    yaraerr "github.com/VirusTotal/go-yara-parser/error"
)

// Necessary types for flexgo
type YYtype interface{}
type YYcontext interface{}

// Global YYtext - each action sets this to the current yytext
var YYtext string

// Accumulators for gathering groups of tokens as text because text collection
// is like an "inclusive" start condition while the lexer requires "exclusive"
var (
    collect           bool  // condition text
    conditionBuilder  strings.Builder
    collectText       bool  // string/regex/etc text
    textBuilder       strings.Builder
)

  // This comment applies to the YY_USER_ACTION macro, which is having
  // a problem with comments...
  // For condition, the colons and whitespace will be collected in the
  // prefix and the right brace for the suffix. Use strings.TrimLeft/Right


}

%{

YY_USER_ACTION(
  YYtext = string(yytext)

  if collect {
    conditionBuilder.Write(yytext)
  }

  if collectText {
    textBuilder.Write(yytext)
  }
)

// Define a constant for end-of-file
const eof = 0

// These globals must be accessible to the goyacc parser.
// Bear in mind that the xx prefix is used because the parser is generated
// with this prefix in order to avoid name collisions.
var yylval *xxSymType
var err error // Actually, this is global for lexer action access.

%}

%option reentrant bison-bridge
%option nounput
%option never-interactive
%option yylineno
%option prefix="yara_yy"

%option verbose
%option warn

%x str
%x regexp
%x include
%x comment

digit         [0-9]
letter        [a-zA-Z]
hexdigit      [a-fA-F0-9]
octdigit      [0-7]

%%

"condition" {
    collect = true
    conditionBuilder.Reset()
    return _CONDITION_
}

".."                    { return _DOT_DOT_;     }
"<"                     { return _LT_;          }
">"                     { return _GT_;          }
"<="                    { return _LE_;          }
">="                    { return _GE_;          }
"=="                    { return _EQ_;          }
"!="                    { return _NEQ_;         }
"<<"                    { return _SHIFT_LEFT_;  }
">>"                    { return _SHIFT_RIGHT_; }
"private"               { return _PRIVATE_;     }
"global"                { return _GLOBAL_;      }
"rule"                  { return _RULE_;        }
"meta"                  { return _META_;        }
"strings"               { return _STRINGS_;     }
"ascii"                 { return _ASCII_;       }
"wide"                  { return _WIDE_;        }
"xor"                   { return _XOR_;         }
"fullword"              { return _FULLWORD_;    }
"nocase"                { return _NOCASE_;      }
"condition"             { return _CONDITION_;   }
"true"                  { return _TRUE_;        }
"false"                 { return _FALSE_;       }
"not"                   { return _NOT_;         }
"and"                   { return _AND_;         }
"or"                    { return _OR_;          }
"at"                    { return _AT_;          }
"in"                    { return _IN_;          }
"of"                    { return _OF_;          }
"them"                  { return _THEM_;        }
"for"                   { return _FOR_;         }
"all"                   { return _ALL_;         }
"any"                   { return _ANY_;         }
"entrypoint"            { return _ENTRYPOINT_;  }
"filesize"              { return _FILESIZE_;    }
"matches"               { return _MATCHES_;     }
"contains"              { return _CONTAINS_;    }
"import"                { return _IMPORT_;      }

"{"                     { return _LBRACE_; }
"}"                     { 
                          if collect {
                            collect = false
                          }
                          return _RBRACE_;
                        }
"include"               { return _INCLUDE_; }

"/*"                    { BEGIN (comment);       }
<comment>"*/"           { BEGIN (INITIAL);       }
<comment>(.|\n)         { /* skip comments */   }


"//"[^\n]*              { /* skip single-line comments */ }

<<EOF>> { return eof }


$({letter}|{digit}|_)*"*"  {
  yylval.s = string(yytext)
  return _STRING_IDENTIFIER_WITH_WILDCARD_;
}


$({letter}|{digit}|_)*  {
  yylval.s = string(yytext)
  return _STRING_IDENTIFIER_;
}


#({letter}|{digit}|_)*  {
  yylval.s = string(yytext)
  return _STRING_COUNT_;
}


@({letter}|{digit}|_)*  {
  yylval.s = string(yytext)
  return _STRING_OFFSET_;
}


!({letter}|{digit}|_)*  {
  yylval.s = string(yytext)
  return _STRING_LENGTH_;
}


u?int(8|16|32)(be)? {
  yylval.s = string(yytext)
  return _INTEGER_FUNCTION_;
}


({letter}|_)({letter}|{digit}|_)*  {
  yylval.s = string(yytext)
  return _IDENTIFIER_;
}


{digit}+(MB|KB){0,1}  {
  var err error
  s := strings.TrimRight(YYtext, "MKB")
  yylval.i64, err = strconv.ParseInt(s, 10, 64)
  if err != nil {
      panic(fmt.Errorf("Number conversion error: %s", err))
  }

  if strings.HasSuffix(YYtext, "KB") {
      if yylval.i64 > math.MaxInt64 / 1024 {
          err := fmt.Errorf("Integer overflow: %s; max %d",
              YYtext, math.MaxInt64)
          panic(err)
      } else {
          yylval.i64 *= 1024
      }
  } else if strings.HasSuffix(YYtext, "MB") {
      if yylval.i64 > math.MaxInt64 / 1048576 {
          err := fmt.Errorf("Integer overflow: %s; max %d",
              YYtext, math.MaxInt64)
          panic(err)
      } else {
          yylval.i64 *= 1048576
      }
  }
  return _NUMBER_;
}

{digit}+"."{digit}+  {
  return _DOUBLE_;
}

0x{hexdigit}+  {
  var err error
  yylval.i64, err = strconv.ParseInt(YYtext, 0, 64)
  if err != nil {
      panic(fmt.Errorf("Number conversion error: %s", err))
  }

  return _NUMBER_;
}

0o{octdigit}+  {
  var err error
  s := strings.TrimLeft(YYtext, "0o")
  yylval.i64, err = strconv.ParseInt(s, 8, 64)
  if err != nil {
      panic(fmt.Errorf("Number conversion error: %s", err))
  }
  return _NUMBER_;
}


<str>\"   {     /* saw closing quote - all done */

  // NOTE: textBuilder.String() will end with `"` char
  collectText = false
  yylval.s = strings.TrimSuffix(textBuilder.String(), `"`)

  BEGIN (INITIAL);

  return _TEXT_STRING_;
}


<str>\\t   {
}


<str>\\n   {
}


<str>\\\"   {
}


<str>\\\\   {
}


<str>\\x{hexdigit}{2} {
}


<str>[^\\\n\"]+   { }


<str>\n  {
  panic(yaraerr.Error{ yaraerr.UnterminatedStringError, "" })
}


<str>\\(.|\n) {
  panic(yaraerr.Error{ yaraerr.IllegalEscapeSequenceError, "" })
}


<regexp>\/i?s?  {
  collectText = false

  txt := strings.TrimSuffix(textBuilder.String(), YYtext)
  
  var mods data.StringModifiers

  for _, c := range YYtext {
      switch c {
      case 'i':
          mods.I = proto.Bool(true)

      case 's':
          mods.S = proto.Bool(true)

      case '/':
          // Ignore

      default:
          // Should be impossible
          panic(yaraerr.Error{ yaraerr.InvalidRegexModifierError, fmt.Sprintf(`"%c"`, c) })
      }
  }

  yylval.reg = data.Regexp {
      Text: &txt,
      Modifiers: &mods,
  }

  BEGIN (INITIAL);
  return _REGEXP_;
}


<regexp>\\\/  {
}


<regexp>\\. {
}


<regexp>[^/\n\\]+ { }


<regexp>\n  {
  panic(yaraerr.Error{ yaraerr.UnterminatedRegexError, "" })
}


\"  {
  collectText = true
  textBuilder.Reset()
  BEGIN (str);
}


"/"  {
  collectText = true
  textBuilder.Reset()
  BEGIN (regexp);
}


\{(({hexdigit}|[ \-|\?\[\]\(\)\n\r\t]|\/\*[^*]*\*\/)+|\/\/.*)+\}  {
  // Match hex-digits with whitespace or comments. The latter are stripped
  // out by hex_lexer.l

  // NOTE: The above comment may not apply. We plan to not use hex_lexer.l

  // No need to collect like str and regexp start conditions
  hexReader := strings.NewReader(YYtext)

  hexString, err := hex.Parse(hexReader)
  if err != nil {
    panic(err)
  }
  yylval.hextokens = &hexString

  return _HEX_STRING_;
}


[ \t\r\n]   /* skip whitespace */

.   {

  r := int(yytext[0])

  if r >= 32 && r < 127 {
    return r
  }

  panic(yaraerr.Error{ yaraerr.NonAsciiByteError, fmt.Sprintf(`"%d"`, r) })
}

%%
