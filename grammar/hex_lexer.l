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

%{

%}

%option reentrant bison-bridge
%option noyywrap
%option nounistd
%option noinput
%option nounput
%option never-interactive
%option yylineno
%option prefix="hex_yy"

%option outfile="lex.yy.go"

%option verbose
%option warn

digit         [0-9]
letter        [a-zA-Z]
hexdigit      [a-fA-F0-9]

%x comment
%x range

%%


<INITIAL>{hexdigit}{2}  {
  return _BYTE_;
}

<INITIAL>{hexdigit}\?  {
  return _MASKED_BYTE_;
}

\?{hexdigit}  {
  return _MASKED_BYTE_;
}

\?\? {
  return _MASKED_BYTE_;
}

\[ {

  BEGIN(range);
  return yytext[0];
}

"/*"(.|\n)*"*/"    // skip comments

"//".*             // skip single-line comments

<range>\- {
  return yytext[0];
}

<range>{digit}+ {
  return _NUMBER_;
}

<range>\] {

  BEGIN(INITIAL);
  return yytext[0];
}

<range>[ \t\r\n]   // skip whitespaces

<range>. {

  /*
  yyerror(yyscanner, lex_env, "invalid character in hex string jump");
  yyterminate();
  */
}

[ \t\r\n]         // skip whitespaces

[{}()|]  {        // pass valid characters to the parser

  return yytext[0];
}

. {               // reject all other characters

  /*
  yyerror(yyscanner, lex_env, "invalid character in hex string");
  yyterminate();
  */
}

%%
