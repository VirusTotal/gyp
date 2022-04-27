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

%{
package parser

import (
    "strings"
    "github.com/VirusTotal/gyp/ast"
    gyperror "github.com/VirusTotal/gyp/error"
)

type modifiers uint64

const (
    _                   = iota // ignore first value by assigning to blank identifier
    ModGlobal modifiers = 1 << iota
    ModPrivate
    ModASCII
    ModWide
    ModXor
    ModFullword
    ModNocase
    ModBase64
    ModBase64Wide
)

type stringModifiers struct {
  modifiers
  XorMin int32
  XorMax int32
  Base64Alphabet string
}

%}

// yara-parser: we have 'const eof = 0' in lexer.l
// Token that marks the end of the original file.
// %token _END_OF_FILE_  0

// TODO: yara-parser: https://github.com/VirusTotal/yara/blob/v3.8.1/libyara/lexer.l#L285
// Token that marks the end of included files, we can't use  _END_OF_FILE_
// because bison stops parsing when it sees _END_OF_FILE_, we want to be
// be able to identify the point where an included file ends, but continuing
// parsing any content that follows.
%token _END_OF_INCLUDED_FILE_

%token _DOT_DOT_
%token _RULE_
%token _PRIVATE_
%token _GLOBAL_
%token _META_
%token _STRINGS_
%token _CONDITION_
%token <s> _IDENTIFIER_
%token <s> _STRING_IDENTIFIER_
%token <s> _STRING_COUNT_
%token <s> _STRING_OFFSET_
%token <s> _STRING_LENGTH_
%token <s> _STRING_IDENTIFIER_WITH_WILDCARD_
%token <i64> _NUMBER_
%token <f64> _DOUBLE_
%token <s> _INTEGER_FUNCTION_
%token <s> _TEXT_STRING_
%token <hexTokens> _HEX_STRING_
%token <reg> _REGEXP_
%token <mod> _ASCII_
%token <mod> _WIDE_
%token _XOR_
%token <mod> _NOCASE_
%token <mod> _FULLWORD_
%token <mod> _BASE64_
%token <mod> _BASE64WIDE_
%token _AT_
%token _FILESIZE_
%token _ENTRYPOINT_
%token _ALL_
%token _ANY_
%token _NONE_
%token _IN_
%token _OF_
%token _FOR_
%token _THEM_
%token _MATCHES_
%token _CONTAINS_
%token _ICONTAINS_
%token _STARTSWITH_
%token _ISTARTSWITH_
%token _ENDSWITH_
%token _IENDSWITH_
%token _IEQUALS_
%token _IMPORT_
%token _TRUE_
%token _FALSE_
%token _INCLUDE_
%token _DEFINED_

%left _OR_
%left _AND_
%right _NOT_ _DEFINED_
%left '|'
%left '^'
%left '&'
%left _EQ_ _NEQ_ _ICONTAINS_ _STARTSWITH_ _ENDSWITH_ _ISTARTSWITH_ _IENDSWITH_ _IEQUALS_ _MATCHES_
%left _LT_ _LE_ _GT_ _GE_
%left _SHIFT_LEFT_ _SHIFT_RIGHT_
%left '+' '-'
%left '*' '\\' '%'
%right '~' UNARY_MINUS

%type <s>         import
%type <rule>      rule
%type <ss>        tags
%type <ss>        tag_list
%type <meta>      meta_declaration
%type <metas>     meta_declarations
%type <metas>     meta
%type <yss>       strings
%type <ys>        string_declaration
%type <yss>       string_declarations
%type <smod>      string_modifier
%type <smod>      string_modifiers
%type <mod>       regexp_modifier
%type <mod>       regexp_modifiers
%type <mod>       hex_modifier
%type <mod>       hex_modifiers
%type <mod>       rule_modifier
%type <mod>       rule_modifiers
%type <expr>      condition
%type <expr>      expression
%type <expr>      boolean_expression
%type <expr>      primary_expression
%type <expr>      identifier
%type <exprs>     arguments_list
%type <exprs>     arguments
%type <expr>      for_expression
%type <exprs>     integer_enumeration
%type <node>      iterator
%type <node>      integer_set
%type <node>      string_set
%type <reg>       regexp
%type <rng>       range
%type <ss>        for_variables
%type <exprs>     string_enumeration
%type <si>        string_enumeration_item
%type <node>      rule_set
%type <exprs>     rule_enumeration
%type <ident>     rule_enumeration_item


%union {
    i64           int64
    f64           float64
    s             string
    ss            []string
    reg           *ast.LiteralRegexp
    hexTokens     []ast.HexToken
    mod           modifiers
    smod          stringModifiers
    rule          *ast.Rule
    meta          *ast.Meta
    metas         []*ast.Meta
    ys            ast.String
    yss           []ast.String
    node          ast.Node
    nodes         []ast.Node
    rng           *ast.Range
    expr          ast.Expression
    exprs         []ast.Expression
    si            *ast.StringIdentifier
    sis           []*ast.StringIdentifier
    ident         *ast.Identifier

    // lineno is not a symbol type, it's the line number where the symbol
    // appears in the source file. This is a little hack used for passing
    // the line number where each token appears from the lexer to the parser.
    // This relies on the fact that Go doesn't implement unions, and therefore
    // goyacc actually uses a struct for passing around symbol values. Being
    // a struct those values can contain both the value itself (in some of
    // the fields listed above) and the line number. This wouldn't work with
    // C code produced by yacc, as this would be a union instead of a struct.
    //
    // This can be used within rule actions as:
    //
    //  lineNumber := $<lineno>1
    //
    // In the example lineNumber will hold the line number for the first
    // symbol in the production rule. The value for the symbol itself would
    // be $1 as usual. Similarly $<lineno>N will return the line number for
    // the N-th symbol in the production rule.

    lineno        int
}


%%

rules
    : /* empty */
    | rules rule
      {
        ruleSet := asLexer(yrlex).ruleSet
        ruleSet.Rules = append(ruleSet.Rules, $2)
      }
    | rules import
      {
        ruleSet := asLexer(yrlex).ruleSet
        ruleSet.Imports = append(ruleSet.Imports, $2)
      }
    | rules _INCLUDE_ _TEXT_STRING_
      {
        ruleSet := asLexer(yrlex).ruleSet
        ruleSet.Includes = append(ruleSet.Includes, $3)
      }
    | rules _END_OF_INCLUDED_FILE_
      {

      }
    ;


import
    : _IMPORT_ _TEXT_STRING_
      {
        if err := validateAscii($2); err != nil {
          return asLexer(yrlex).setError(
            gyperror.InvalidAsciiError, err.Error())
        }

        $$ = $2
      }
    ;


rule
    : rule_modifiers _RULE_ _IDENTIFIER_
      {
        lexer := asLexer(yrlex)

        // Forbid duplicate rules
        for _, r := range lexer.ruleSet.Rules {
            if $3 == r.Identifier {
              return lexer.setError(
                gyperror.DuplicateRuleError, `duplicate rule "%s"`, $3)
            }
        }

        $$ = &ast.Rule{
            LineNo: $<lineno>2,
            Global: $1 & ModGlobal == ModGlobal,
            Private: $1 & ModPrivate == ModPrivate,
            Identifier: $3,
        }
      }
      tags '{' meta strings
      {
        // Check for duplicate strings.
        m := make(map[string]bool)
        for _, str := range $8 {
          ident := str.GetIdentifier()
          // Anonymous strings (no identifiers) are fine.
          if ident == "" {
            continue
          }
          if m[ident] {
            return asLexer(yrlex).setErrorWithLineNumber(
              gyperror.DuplicateStringError,
              str.GetLineNo(),
              `rule "%s" duplicate string identifier "%s"`, $<rule>4.Identifier, ident)
          }
          m[ident] = true
        }
        $<rule>4.Tags = $5
        $<rule>4.Meta = $7
        $<rule>4.Strings = $8
      }
      condition '}'
      {
        $<rule>4.Condition = $10
        $$ = $<rule>4
      }
    ;


meta
    : /* empty */
      {
        $$ = []*ast.Meta{}
      }
    | _META_ ':' meta_declarations
      {
        $$ = $3
      }
    ;


strings
    : /* empty */
      {
        $$ = []ast.String{}
      }
    | _STRINGS_ ':' string_declarations
      {
        $$ = $3
      }
    ;


condition
    : _CONDITION_ ':' boolean_expression
      {
        $$ = $3
      }
    ;


rule_modifiers
    : /* empty */
      {
        $$ = 0
      }
    | rule_modifiers rule_modifier
      {
        $$ = $1 | $2
      }
    ;


rule_modifier
    : _PRIVATE_
      {
        $$ = ModPrivate
      }
    | _GLOBAL_
      {
        $$ = ModGlobal
      }
    ;


tags
    : /* empty */
      {
        $$ = []string{}
      }
    | ':' tag_list
      {
        $$ = $2
      }
    ;


tag_list
    : _IDENTIFIER_
      {
        $$ = []string{$1}
      }
    | tag_list _IDENTIFIER_
      {
        lexer := asLexer(yrlex)

        for _, tag := range $1 {
          if tag == $2 {
            return lexer.setError(
                gyperror.DuplicateTagError, `duplicate tag "%s"`, $2)
          }
        }

        $$ = append($1, $2)
      }
    ;


meta_declarations
    : meta_declaration
      {
        $$ = []*ast.Meta{$1}
      }
    | meta_declarations meta_declaration
      {
        $$ = append($1, $2)
      }
    ;


meta_declaration
    : _IDENTIFIER_ '=' _TEXT_STRING_
      {
        $$ = &ast.Meta{
          Key: $1,
          Value: $3,
        }
      }
    | _IDENTIFIER_ '=' _NUMBER_
      {
        $$ = &ast.Meta{
          Key: $1,
          Value: $3,
        }
      }
    | _IDENTIFIER_ '=' '-' _NUMBER_
      {
        $$ = &ast.Meta{
          Key: $1,
          Value: -$4,
        }
      }
    | _IDENTIFIER_ '=' _TRUE_
      {
        $$ = &ast.Meta{
          Key: $1,
          Value: true,
        }
      }
    | _IDENTIFIER_ '=' _FALSE_
      {
        $$ = &ast.Meta{
          Key: $1,
          Value: false,
        }
      }
    ;


string_declarations
    : string_declaration
      {
        $$ = []ast.String{$1}
      }
    | string_declarations string_declaration
      {
        $$ = append($1, $2)
      }
    ;


string_declaration
    : _STRING_IDENTIFIER_ '=' _TEXT_STRING_
      {
         if err := validateUTF8($3); err != nil {
           return asLexer(yrlex).setError(
             gyperror.InvalidUTF8Error, err.Error())
         }
      }
      string_modifiers
      {
        $$ = &ast.TextString{
          BaseString : ast.BaseString{
          	Identifier: strings.TrimPrefix($1, "$"),
          	LineNo: $<lineno>1,
          },
          ASCII: $5.modifiers & ModASCII != 0,
          Wide: $5.modifiers & ModWide != 0,
          Nocase: $5.modifiers & ModNocase != 0,
          Fullword: $5.modifiers & ModFullword != 0,
          Private: $5.modifiers & ModPrivate != 0,
          Base64: $5.modifiers & ModBase64 != 0,
          Base64Wide: $5.modifiers & ModBase64Wide != 0,
          Base64Alphabet: $5.Base64Alphabet,
          Xor: $5.modifiers & ModXor != 0,
          XorMin: $5.XorMin,
          XorMax: $5.XorMax,
          Value: $3,
        }
      }
    | _STRING_IDENTIFIER_ '=' _REGEXP_ regexp_modifiers
      {
        $$ = &ast.RegexpString{
          BaseString : ast.BaseString{
          	Identifier: strings.TrimPrefix($1, "$"),
          	LineNo: $<lineno>1,
          },
          ASCII: $4 & ModASCII != 0,
          Wide: $4 & ModWide != 0,
          Nocase: $4 & ModNocase != 0,
          Fullword: $4 & ModFullword != 0,
          Private: $4 & ModPrivate != 0,
          Regexp: $3,
        }
      }
    | _STRING_IDENTIFIER_ '=' _HEX_STRING_ hex_modifiers
      {
        $$ = &ast.HexString{
          BaseString : ast.BaseString{
          	Identifier: strings.TrimPrefix($1, "$"),
          	LineNo: $<lineno>1,
          },
          Private: $4 & ModPrivate != 0,
          Tokens: $3,
        }
      }
    ;


string_modifiers
    : /* empty */
      {
        $$ = stringModifiers{}
      }
    | string_modifiers string_modifier
      {
        if $1.modifiers & $2.modifiers != 0 {
          return asLexer(yrlex).setError(
            gyperror.DuplicateModifierError, `duplicate modifier`)
        }

        $1.modifiers |= $2.modifiers

        if $2.modifiers & ModXor != 0 {
          $1.XorMin = $2.XorMin
          $1.XorMax = $2.XorMax
        }

        if $2.modifiers & (ModBase64 | ModBase64Wide) != 0 {
          $1.Base64Alphabet = $2.Base64Alphabet
        }

        $$ = $1
      }
    ;


string_modifier
    : _WIDE_        { $$ = stringModifiers{modifiers: ModWide} }
    | _ASCII_       { $$ = stringModifiers{modifiers: ModASCII} }
    | _NOCASE_      { $$ = stringModifiers{modifiers: ModNocase} }
    | _FULLWORD_    { $$ = stringModifiers{modifiers: ModFullword} }
    | _PRIVATE_     { $$ = stringModifiers{modifiers: ModPrivate} }
    | _BASE64_      { $$ = stringModifiers{modifiers: ModBase64} }
    | _BASE64WIDE_  { $$ = stringModifiers{modifiers: ModBase64Wide} }
    | _BASE64_ '(' _TEXT_STRING_ ')'
       {
         if err := validateAscii($3); err != nil {
           return asLexer(yrlex).setError(
             gyperror.InvalidAsciiError, err.Error())
         }

         if len($3) != 64 {
           return asLexer(yrlex).setError(
             gyperror.InvalidStringModifierError,
             "length of base64 alphabet must be 64")
         }

         $$ = stringModifiers{
           modifiers: ModBase64,
           Base64Alphabet: $3,
         }
       }
     | _BASE64WIDE_ '(' _TEXT_STRING_ ')'
        {
          if err := validateAscii($3); err != nil {
            return asLexer(yrlex).setError(
              gyperror.InvalidAsciiError, err.Error())
          }

          if len($3) != 64 {
            return asLexer(yrlex).setError(
              gyperror.InvalidStringModifierError,
              "length of base64 alphabet must be 64")
          }

          $$ = stringModifiers{
            modifiers: ModBase64Wide,
            Base64Alphabet: $3,
          }
        }
    | _XOR_
      {
        $$ = stringModifiers{
          modifiers: ModXor,
          XorMin: 0,
          XorMax: 255,
        }
      }
    | _XOR_ '(' _NUMBER_ ')'
      {
        $$ = stringModifiers{
          modifiers: ModXor,
          XorMin: int32($3),
          XorMax: int32($3),
        }
      }
    | _XOR_ '(' _NUMBER_ '-' _NUMBER_ ')'
      {
        lexer := asLexer(yrlex)

        if $3 < 0 {
          return lexer.setError(
            gyperror.InvalidStringModifierError,
            "lower bound for xor range exceeded (min: 0)")
        }

        if $5 > 255 {
          return lexer.setError(
            gyperror.InvalidStringModifierError,
            "upper bound for xor range exceeded (max: 255)")
        }

        if $3 > $5 {
          return lexer.setError(
            gyperror.InvalidStringModifierError,
            "xor lower bound exceeds upper bound")
        }

        $$ = stringModifiers{
          modifiers: ModXor,
          XorMin: int32($3),
          XorMax: int32($5),
        }
      }
    ;


regexp_modifiers
    : /* empty */
      {
        $$ = 0
      }
    | regexp_modifiers regexp_modifier
      {
        $$ = $1 | $2
      }
    ;


regexp_modifier
    : _WIDE_        { $$ = ModWide }
    | _ASCII_       { $$ = ModASCII }
    | _NOCASE_      { $$ = ModNocase }
    | _FULLWORD_    { $$ = ModFullword }
    | _PRIVATE_     { $$ = ModPrivate }
    ;


hex_modifiers
    : /* empty */
      {
        $$ = 0
      }
    | hex_modifiers hex_modifier
      {
        $$ = $1 | $2
      }
    ;


hex_modifier
    : _PRIVATE_     { $$ = ModPrivate }
    ;


identifier
    : _IDENTIFIER_
      {
        $$ = &ast.Identifier{Identifier: $1}
      }
    | identifier '.' _IDENTIFIER_
      {
        $$ = &ast.MemberAccess{
          Container: $1,
          Member: $3,
        }
      }
    | identifier '[' primary_expression ']'
      {
        $$ = &ast.Subscripting{
          Array: $1,
          Index: $3,
        }
      }
    | identifier '(' arguments ')'
      {
        $$ = &ast.FunctionCall{
          Callable: $1,
          Arguments: $3,
        }
      }
    ;


arguments
    : /* empty */
      {
        $$ = []ast.Expression{}
      }
    | arguments_list
     {
        $$ = $1
     }


arguments_list
    : expression
      {
        $$ = []ast.Expression{$1}
      }
    | arguments_list ',' expression
      {
        $$ = append($1, $3)
      }
    ;


regexp
    : _REGEXP_
      {
        $$ = $1
      }
    ;


boolean_expression
    : expression
      {
        $$ = $1
      }
    ;


expression
    : _TRUE_
      {
        $$ = ast.KeywordTrue
      }
    | _FALSE_
      {
        $$ = ast.KeywordFalse
      }
    | primary_expression _MATCHES_ regexp
      {
        $$ = &ast.Operation{
          Operator: ast.OpMatches,
          Operands: []ast.Expression{$1, $3},
        }
      }
    | primary_expression _CONTAINS_ primary_expression
      {
        $$ = &ast.Operation{
          Operator: ast.OpContains,
          Operands: []ast.Expression{$1, $3},
        }
      }
    | primary_expression _ICONTAINS_ primary_expression
      {
        $$ = &ast.Operation{
          Operator: ast.OpIContains,
          Operands: []ast.Expression{$1, $3},
        }
      }
    | primary_expression _STARTSWITH_ primary_expression
      {
        $$ = &ast.Operation{
          Operator: ast.OpStartsWith,
          Operands: []ast.Expression{$1, $3},
        }
      }
     | primary_expression _ISTARTSWITH_ primary_expression
       {
         $$ = &ast.Operation{
           Operator: ast.OpIStartsWith,
           Operands: []ast.Expression{$1, $3},
         }
       }
    | primary_expression _ENDSWITH_ primary_expression
      {
        $$ = &ast.Operation{
          Operator: ast.OpEndsWith,
          Operands: []ast.Expression{$1, $3},
        }
      }
     | primary_expression _IENDSWITH_ primary_expression
       {
         $$ = &ast.Operation{
           Operator: ast.OpIEndsWith,
           Operands: []ast.Expression{$1, $3},
         }
       }
     | primary_expression _IEQUALS_ primary_expression
       {
         $$ = &ast.Operation{
           Operator: ast.OpIEquals,
           Operands: []ast.Expression{$1, $3},
         }
      }
    | _STRING_IDENTIFIER_
      {
        $$ = &ast.StringIdentifier{
          Identifier: strings.TrimPrefix($1, "$"),
        }
      }
    | _STRING_IDENTIFIER_ _AT_ primary_expression
      {
        $$ = &ast.StringIdentifier{
          Identifier: strings.TrimPrefix($1, "$"),
          At: $3,
        }
      }
    | _STRING_IDENTIFIER_ _IN_ range
      {
        $$ = &ast.StringIdentifier{
          Identifier: strings.TrimPrefix($1, "$"),
          In: $3,
        }
      }
    | _FOR_ for_expression for_variables _IN_ iterator ':' '(' boolean_expression ')'
      {
        $$ = &ast.ForIn{
          Quantifier: $2,
          Variables: $3,
          Iterator: $5,
          Condition: $8,
        }
      }
    | _FOR_ for_expression _OF_ string_set ':' '(' boolean_expression ')'
      {
        $$ = &ast.ForOf{
          Quantifier: $2,
          Strings: $4,
          Condition:  $7,
        }
      }
    | for_expression _OF_ string_set _IN_ range
      {
        $$ = &ast.Of{
          Quantifier: $1,
          Strings: $3,
          In: $5,
        }
      }
    | for_expression _OF_ string_set
      {
        $$ = &ast.Of{
          Quantifier: $1,
          Strings: $3,
        }
      }
    | for_expression _OF_ rule_set
      {
        $$ = &ast.Of{
          Quantifier: $1,
          Rules: $3,
        }
      }
    | primary_expression '%' _OF_ string_set
      {
        $$ = &ast.Of{
          Quantifier: &ast.Percentage{$1},
          Strings: $4,
        }
      }
    | primary_expression '%' _OF_ rule_set
      {
        $$ = &ast.Of{
          Quantifier: &ast.Percentage{$1},
          Rules: $4,
        }
      }
    | _NOT_ boolean_expression
      {
        $$ = &ast.Not{$2}
      }
    | _DEFINED_ boolean_expression
      {
        $$ = &ast.Defined{$2}
      }
    | boolean_expression _AND_ boolean_expression
      {
        $$ = operation(ast.OpAnd, $1, $3)
      }
    | boolean_expression _OR_ boolean_expression
      {
        $$ = operation(ast.OpOr, $1, $3)
      }
    | primary_expression _LT_ primary_expression
      {
        $$ = &ast.Operation{
          Operator: ast.OpLessThan,
          Operands: []ast.Expression{$1, $3},
        }
      }
    | primary_expression _GT_ primary_expression
      {
        $$ = &ast.Operation{
          Operator: ast.OpGreaterThan,
          Operands: []ast.Expression{$1, $3},
        }
      }
    | primary_expression _LE_ primary_expression
      {
        $$ = &ast.Operation{
          Operator: ast.OpLessOrEqual,
          Operands: []ast.Expression{$1, $3},
        }
      }
    | primary_expression _GE_ primary_expression
      {
        $$ = &ast.Operation{
          Operator: ast.OpGreaterOrEqual,
          Operands: []ast.Expression{$1, $3},
        }
      }
    | primary_expression _EQ_ primary_expression
      {
        $$ = &ast.Operation{
          Operator: ast.OpEqual,
          Operands: []ast.Expression{$1, $3},
        }
      }
    | primary_expression _NEQ_ primary_expression
      {
        $$ = &ast.Operation{
          Operator: ast.OpNotEqual,
          Operands: []ast.Expression{$1, $3},
        }
      }
    | primary_expression
      {
        $$ = $1
      }
    |'(' expression ')'
      {
        $$ = &ast.Group{$2}
      }
    ;


integer_set
    : '(' integer_enumeration ')'
      {
        $$ = &ast.Enum{Values: $2}
      }
    | range
      {
        $$ = $1
      }
    ;


range
    : '(' primary_expression _DOT_DOT_  primary_expression ')'
      {
        $$ = &ast.Range{
          Start: $2,
          End: $4,
        }
      }
    ;


integer_enumeration
    : primary_expression
      {
        $$ = []ast.Expression{$1}
      }
    | integer_enumeration ',' primary_expression
      {
        $$ = append($1, $3)
      }
   ;


string_set
    : '(' string_enumeration ')'
      {
        $$ = &ast.Enum{Values: $2}
      }
    | _THEM_
      {
        $$ = ast.KeywordThem
      }
    ;


string_enumeration
    : string_enumeration_item
      {
        $$ = []ast.Expression{$1}
      }
    | string_enumeration ',' string_enumeration_item
      {
        $$ = append($1, $3)
      }
    ;


string_enumeration_item
    : _STRING_IDENTIFIER_
      {
        $$ = &ast.StringIdentifier{
          Identifier: strings.TrimPrefix($1, "$"),
        }
      }
    | _STRING_IDENTIFIER_WITH_WILDCARD_
      {
        $$ = &ast.StringIdentifier{
          Identifier: strings.TrimPrefix($1, "$"),
        }
      }
    ;


rule_set
    : '(' rule_enumeration ')'
      {
        $$ = &ast.Enum{Values: $2}
      }
    ;


rule_enumeration
    : rule_enumeration_item
      {
        $$ = []ast.Expression{$1}
      }
    | rule_enumeration ',' rule_enumeration_item
      {
        $$ = append($1, $3)
      }
    ;


rule_enumeration_item
    : _IDENTIFIER_
      {
        $$ = &ast.Identifier{Identifier: $1}
      }
    | _IDENTIFIER_ '*'
      {
        $$ = &ast.Identifier{Identifier: $1 + "*"}
      }
    ;


for_expression
    : primary_expression
      {
        $$ = $1
      }
    | _ALL_
      {
        $$ = ast.KeywordAll
      }
    | _ANY_
      {
        $$ = ast.KeywordAny
      }
    | _NONE_
      {
        $$ = ast.KeywordNone
      }
    ;


for_variables
    : _IDENTIFIER_
      {
        $$ = []string{$1}
      }
    | for_variables ',' _IDENTIFIER_
      {
        $$ = append($1, $3)
      }
    ;

iterator
    : identifier
      {
        $$ = $1
      }
    | integer_set
      {
        $$ = $1
      }
    ;


primary_expression
    : '(' primary_expression ')'
      {
        $$ = &ast.Group{$2}
      }
    | _FILESIZE_
      {
        $$ = ast.KeywordFilesize
      }
    | _ENTRYPOINT_
      {
        $$ = ast.KeywordEntrypoint
      }
    | _INTEGER_FUNCTION_ '(' primary_expression ')'
      {
        $$ = &ast.FunctionCall{
          Callable: &ast.Identifier{Identifier: $1},
          Arguments: []ast.Expression{$3},
        }
      }
    | _NUMBER_
      {
        $$ = &ast.LiteralInteger{$1}
      }
    | _DOUBLE_
      {
        $$ = &ast.LiteralFloat{$1}
      }
    | _TEXT_STRING_
      {
         if err := validateUTF8($1); err != nil {
           return asLexer(yrlex).setError(
             gyperror.InvalidUTF8Error, err.Error())
         }

        $$ = &ast.LiteralString{$1}
      }
    | _STRING_COUNT_ _IN_ range
      {
        $$ = &ast.StringCount{
          Identifier: strings.TrimPrefix($1, "#"),
          In: $3,
        }
      }
    | _STRING_COUNT_
      {
        $$ = &ast.StringCount{
          Identifier: strings.TrimPrefix($1, "#"),
        }
      }
    | _STRING_OFFSET_ '[' primary_expression ']'
      {
        $$ = &ast.StringOffset{
          Identifier: strings.TrimPrefix($1, "@"),
          Index: $3,
        }
      }
    | _STRING_OFFSET_
      {
        $$ = &ast.StringOffset{
          Identifier: strings.TrimPrefix($1, "@"),
        }
      }
    | _STRING_LENGTH_ '[' primary_expression ']'
      {
        $$ = &ast.StringLength{
          Identifier: strings.TrimPrefix($1, "!"),
          Index: $3,
        }
      }
    | _STRING_LENGTH_
      {
        $$ = &ast.StringLength{
          Identifier: strings.TrimPrefix($1, "!"),
        }
      }
    | identifier
      {
        $$ = $1
      }
    | '-' primary_expression %prec UNARY_MINUS
      {
        $$ = &ast.Minus{$2}
      }
    | primary_expression '+' primary_expression
      {
        $$ = operation(ast.OpAdd, $1, $3)
      }
    | primary_expression '-' primary_expression
      {
        $$ = operation(ast.OpSub, $1, $3)
      }
    | primary_expression '*' primary_expression
      {
        $$ = operation(ast.OpMul, $1, $3)
      }
    | primary_expression '\\' primary_expression
      {
        $$ = operation(ast.OpDiv, $1, $3)
      }
    | primary_expression '%' primary_expression
      {
        $$ = operation(ast.OpMod, $1, $3)
      }
    | primary_expression '^' primary_expression
      {
        $$ = operation(ast.OpBitXor, $1, $3)
      }
    | primary_expression '&' primary_expression
      {
        $$ = operation(ast.OpBitAnd, $1, $3)
      }
    | primary_expression '|' primary_expression
      {
        $$ = operation(ast.OpBitOr, $1, $3)
      }
    | '~' primary_expression
      {
        $$ = &ast.BitwiseNot{$2}
      }
    | primary_expression _SHIFT_LEFT_ primary_expression
      {
        $$ = operation(ast.OpShiftLeft, $1, $3)
      }
    | primary_expression _SHIFT_RIGHT_ primary_expression
      {
        $$ = operation(ast.OpShiftRight, $1, $3)
      }
    | regexp
      {
        $$ = $1
      }
    ;

%%


// This function takes an operator and two operands and returns a Expression
// representing the operation. If the left operand is an operation of the
// the same kind than the specified by the operator, the right operand is
// simply appended to that existing operation. This implies that the operator
// must be left-associative in order to be used with this function.
func operation(operator ast.OperatorType, left, right ast.Expression) (n ast.Expression) {
  if operation, ok := left.(*ast.Operation); ok && operation.Operator == operator {
    operation.Operands = append(operation.Operands, right)
    n = operation
  } else {
    n = &ast.Operation{
      Operator: operator,
      Operands: []ast.Expression{left, right},
    }
  }
  return n
}
