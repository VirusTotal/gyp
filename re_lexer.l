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

/* Lexical analyzer for regular expressions */

%{

%}

%option reentrant bison-bridge
%option noyywrap
%option nounistd
%option nounput
%option never-interactive
%option yylineno
%option prefix="re_yy"

%option outfile="lex.yy.go"

%option verbose
%option warn

%x char_class

digit         [0-9]
hex_digit     [0-9a-fA-F]

%%

\{{digit}*,{digit}*\} {
  return _RANGE_;
}


\{{digit}+\} {
  return _RANGE_;
}


\[\^ {

  // Start of a negated character class. Example: [^abcd]

  BEGIN(char_class);
}

\[\^\] {

  // Start of character negated class containing a ].
  // Example: [^]abc] this must be interpreted as a class
  // not matching ], a, b, nor c

  BEGIN(char_class);
}


\[\] {

  // Start of character class containing a ].
  // Example: []abc] this must be interpreted as a class
  // matching ], a, b, or c.

  BEGIN(char_class);
}


\[ {

  // Start of character class. Example: [abcd]

  BEGIN(char_class);
}

[^\\\[\(\)\|\$\.\^\+\*\?] {

  // Any non-special character is passed as a CHAR token to the scanner.

  return _CHAR_;
}


\\w {
  return _WORD_CHAR_;
}


\\W {
  return _NON_WORD_CHAR_;
}


\\s {
  return _SPACE_;
}


\\S {
  return _NON_SPACE_;
}


\\d {
  return _DIGIT_;
}


\\D {
  return _NON_DIGIT_;
}


\\b {
  return _WORD_BOUNDARY_;
}

\\B {
  return _NON_WORD_BOUNDARY_;
}


\\{digit}+ {

  /*
  yyerror(yyscanner, lex_env, "backreferences are not allowed");
  yyterminate();
  */
}


\\ {
  /*
  uint8_t c;

  if (read_escaped_char(yyscanner, &c))
  {
    yylval->integer = c;
    return _CHAR_;
  }
  else
  {
    yyerror(yyscanner, lex_env, "illegal escape sequence");
    yyterminate();
  }
  */
}


<char_class>\] {

  // End of character class.

  BEGIN(INITIAL);
  return _CLASS_;
}



<char_class>(\\x{hex_digit}{2}|\\.|[^\\])\-[^]] {

  // A range inside a character class.
  //  [abc0-9]
  //      ^- matching here
}


<char_class>\\w {
}


<char_class>\\W {
}


<char_class>\\s {
}


<char_class>\\S {
}


<char_class>\\d {
}


<char_class>\\D {
}


<char_class>\\ {
}


<char_class>. {

  /*
  if (yytext[0] >= 32 && yytext[0] < 127)
  {
    // A character class (i.e: [0-9a-f]) is represented by a 256-bits vector,
    // here we set to 1 the vector's bit corresponding to the input character.

    LEX_ENV->re_class.bitmap[yytext[0] / 8] |= 1 << yytext[0] % 8;
  }
  else
  {
    yyerror(yyscanner, lex_env, "non-ascii character");
    yyterminate();
  }
  */
}


<char_class><<EOF>> {

  // End of regexp reached while scanning a character class.

  /*
  yyerror(yyscanner, lex_env, "missing terminating ] for character class");
  yyterminate();
  */
}


. {

  /*
  if (yytext[0] >= 32 && yytext[0] < 127)
  {
    return yytext[0];
  }
  else
  {
    yyerror(yyscanner, lex_env, "non-ascii character");
    yyterminate();
  }
  */
}


<<EOF>> {

}

%%
