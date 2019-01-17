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
package grammar

import (
    "fmt"

    "github.com/VirusTotal/go-yara-parser/data"
)

var ParsedRuleset data.RuleSet

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
%token <s> _HEX_STRING_
%token <reg> _REGEXP_
%token <mod> _ASCII_
%token <mod> _WIDE_
%token _XOR_
%token <mod> _NOCASE_
%token <mod> _FULLWORD_
%token _AT_
%token _FILESIZE_
%token _ENTRYPOINT_
%token _ALL_
%token _ANY_
%token _IN_
%token _OF_
%token _FOR_
%token _THEM_
%token _MATCHES_
%token _CONTAINS_
%token _IMPORT_

%token _TRUE_
%token _FALSE_

%token _LBRACE_ _RBRACE_
%token _INCLUDE_

%left _OR_
%left _AND_
%left '|'
%left '^'
%left '&'
%left _EQ_ _NEQ_
%left _LT_ _LE_ _GT_ _GE_
%left _SHIFT_LEFT_ _SHIFT_RIGHT_
%left '+' '-'
%left '*' '\\' '%'
%right _NOT_ '~' UNARY_MINUS

%type <s>    import
%type <yr>   rule
%type <ss>   tags
%type <ss>   tag_list
%type <m>    meta
%type <mps>  meta_declarations
%type <mp>   meta_declaration
%type <yss>  strings
%type <yss>  string_declarations
%type <ys>   string_declaration
%type <mod>  string_modifier
%type <mod>  string_modifiers
%type <rm>   rule_modifier
%type <rm>   rule_modifiers
%type <term> condition
%type <term> boolean_expression
%type <term> expression
%type <pex>  primary_expression
%type <id>   identifier
%type <terms> arguments_list
%type <terms> arguments
%type <reg>  regexp
%type <fex>  for_expression
%type <iset> integer_set
%type <pexs> integer_enumeration
%type <rng>  range
%type <strs> string_set
%type <stri> string_enumeration_item
%type <stris> string_enumeration

%union {
    i64           int64
    f64           float64
    s             string
    ss            []string

    rm            data.RuleModifiers
    m             data.Metas
    mp            data.Meta
    mps           data.Metas
    mod           data.StringModifiers
    reg           data.Regexp
    ys            data.String
    yss           data.Strings
    yr            data.Rule
    term          data.BooleanExpressionTerm
    terms         []data.BooleanExpressionTerm
    pex           data.PrimaryExpression
    pexs          []data.PrimaryExpression
    id            data.Identifier
    fex           data.ForExpression
    iset          data.IntegerSet
    rng           data.Range
    strs          data.StringSet
    stri          data.StringEnumerationItem
    stris         []data.StringEnumerationItem
}


%%

rules
    : /* empty */
    | rules rule {
        ParsedRuleset.Rules = append(ParsedRuleset.Rules, $2)
    }
    | rules import {
        ParsedRuleset.Imports = append(ParsedRuleset.Imports, $2)
    }
    | rules _INCLUDE_ _TEXT_STRING_ {
        ParsedRuleset.Includes = append(ParsedRuleset.Includes, $3)
    }
    | rules _END_OF_INCLUDED_FILE_ { }
    ;


import
    : _IMPORT_ _TEXT_STRING_
      {
          $$ = $2
      }
    ;


rule
    : rule_modifiers _RULE_ _IDENTIFIER_
      {
          $$.Modifiers = $1
          $$.Identifier = $3

          // Forbid duplicate rules
          for _, r := range ParsedRuleset.Rules {
              if $3 == r.Identifier {
                  err := fmt.Errorf(`Duplicate rule "%s"`, $3)
                  panic(err)
              }
          }
      }
      tags _LBRACE_ meta strings
      {
          // $4 is the rule created in above action
          $<yr>4.Tags = $5

          // Forbid duplicate tags
          idx := make(map[string]struct{})
          for _, t := range $5 {
              if _, had := idx[t]; had {
                  msg := fmt.Sprintf(`grammar: Rule "%s" has duplicate tag "%s"`,
                      $<yr>4.Identifier,
                      t)
                  panic(msg)
              }
              idx[t] = struct{}{}
          }

          $<yr>4.Meta = $7

          $<yr>4.Strings = $8

          // Forbid duplicate string IDs, except `$` (anonymous)
          idx = make(map[string]struct{})
          for _, s := range $8 {
              if s.ID == "$" {
                  continue
              }
              if _, had := idx[s.ID]; had {
                  msg := fmt.Sprintf(
                    `grammar: Rule "%s" has duplicated string "%s"`,
                    $<yr>4.Identifier,
                    s.ID)
                  panic(msg)
              }
              idx[s.ID] = struct{}{}
          }
      }
      condition _RBRACE_
      {
          $<yr>4.Condition = $10
          $$ = $<yr>4
      }
    ;


meta
    : /* empty */
      {
        
      }
    | _META_ ':' meta_declarations
      {
          $$ = make(data.Metas, 0, len($3))
          for _, mpair := range $3 {
              // YARA is ok with duplicate keys; we follow suit
              $$ = append($$, mpair)
          }
      }
    ;


strings
    : /* empty */
      {
          $$ = data.Strings{}
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
    : /* empty */ { $$ = data.RuleModifiers{} }
    | rule_modifiers rule_modifier     {
        $$.Private = $$.Private || $2.Private
        $$.Global = $$.Global || $2.Global
    }
    ;


rule_modifier
    : _PRIVATE_      { $$.Private = true }
    | _GLOBAL_       { $$.Global = true }
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
          $$ = append($1, $2)
      }
    ;


meta_declarations
    : meta_declaration                    { $$ = data.Metas{$1} }
    | meta_declarations meta_declaration  { $$ = append($$, $2)}
    ;


meta_declaration
    : _IDENTIFIER_ '=' _TEXT_STRING_
      {
          $$ = data.Meta{$1, $3}
      }
    | _IDENTIFIER_ '=' _NUMBER_
      {
          $$ = data.Meta{$1, $3}
      }
    | _IDENTIFIER_ '=' '-' _NUMBER_
      {
          $$ = data.Meta{$1, -$4}
      }
    | _IDENTIFIER_ '=' _TRUE_
      {
          $$ = data.Meta{$1, true}
      }
    | _IDENTIFIER_ '=' _FALSE_
      {
          $$ = data.Meta{$1, false}
      }
    ;


string_declarations
    : string_declaration                      { $$ = data.Strings{$1} }
    | string_declarations string_declaration  { $$ = append($1, $2) }
    ;


string_declaration
    : _STRING_IDENTIFIER_ '='
      {
          $$.Type = data.TypeString
          $$.ID = $1
      }
      _TEXT_STRING_ string_modifiers
      {
          $<ys>3.Text = $4
          $<ys>3.Modifiers = $5

          $$ = $<ys>3
      }
    | _STRING_IDENTIFIER_ '='
      {
          $$.Type = data.TypeRegex
          $$.ID = $1
      }
      _REGEXP_ string_modifiers
      {
          $<ys>3.Text = $4.Text

          $5.I = $4.Modifiers.I
          $5.S = $4.Modifiers.S

          $<ys>3.Modifiers = $5

          $$ = $<ys>3
      }
    | _STRING_IDENTIFIER_ '=' _HEX_STRING_
      {
          $$.Type = data.TypeHexString
          $$.ID = $1
          $$.Text = $3
      }
    ;


string_modifiers
    : /* empty */                         {
      $$ = data.StringModifiers{}
    }
    | string_modifiers string_modifier    {
          $$ = data.StringModifiers {
              Wide: $1.Wide || $2.Wide,
              ASCII: $1.ASCII || $2.ASCII,
              Nocase: $1.Nocase || $2.Nocase,
              Fullword: $1.Fullword || $2.Fullword,
              Xor: $1.Xor || $2.Xor,
          }
    }
    ;


string_modifier
    : _WIDE_        { $$.Wide = true }
    | _ASCII_       { $$.ASCII = true }
    | _NOCASE_      { $$.Nocase = true }
    | _FULLWORD_    { $$.Fullword = true }
    | _XOR_         { $$.Xor = true }
    ;



identifier
    : _IDENTIFIER_
      {
          $$ = []data.IdentifierItem{{ Identifier: $1 }}
      }
    | identifier '.' _IDENTIFIER_
      {
          $$ =  append($1, data.IdentifierItem{ Identifier: $3 } )
      }
    | identifier '[' primary_expression ']'
      {
          $$ = append($1, data.IdentifierItem{ PrimaryExpression: $3 } )
      }

    | identifier '(' arguments ')'
      {
          $$ = append($1, data.IdentifierItem{ Arguments: $3 })
      }
    ;


arguments
    : /* empty */     { $$ = []data.BooleanExpressionTerm{} }
    | arguments_list  { $$ = $1 }


arguments_list
    : expression
      {
          $$ = []data.BooleanExpressionTerm{$1}
      }
    | arguments_list ',' expression
      {
          $$ = append($1, $3)
      }
    ;


regexp
    : _REGEXP_ { $$ = $1 }
    ;


boolean_expression
    : expression { $$ = $1 }
    ;

expression
    : _TRUE_
      {
          $$ = data.BooleanExpressionTerm{ BoolValue: true }
      }
    | _FALSE_
      {
          $$ = data.BooleanExpressionTerm{ BoolValue: false }
      }
    | primary_expression _MATCHES_ regexp
      {
          $$ = data.BooleanExpressionTerm{
              BinaryExpression: &data.BinaryExpression{
                  Operator: data.MatchesOperator,
                  Left: $1,
                  Right: $3,
              },
          }
      }
    | primary_expression _CONTAINS_ primary_expression
      {
          $$ = data.BooleanExpressionTerm{
              BinaryExpression: &data.BinaryExpression{
                  Operator: data.ContainsOperator,
                  Left: $1,
                  Right: $3,
              },
          }
      }
    | _STRING_IDENTIFIER_
      {
          $$ = data.BooleanExpressionTerm{
              StringIdentifier: $1,
          }
      }
    | _STRING_IDENTIFIER_ _AT_ primary_expression
      {
          $$ = data.BooleanExpressionTerm{
              BinaryExpression: &data.BinaryExpression{
                  Operator: data.AtOperator,
                  Left: $1,
                  Right: $3,
              },
          }
      }
    | _STRING_IDENTIFIER_ _IN_ range
      {
          $$ = data.BooleanExpressionTerm{
              BinaryExpression: &data.BinaryExpression{
                  Operator: data.InOperator,
                  Left: $1,
                  Right: $3,
              },
          }
      }
    | _FOR_ for_expression error { }
    | _FOR_ for_expression _IDENTIFIER_ _IN_ integer_set ':' '(' boolean_expression ')'
      {
          $$ = data.BooleanExpressionTerm{
              ForInExpression: &data.ForInExpression {
                  ForExpression: $2,
                  Identifier: $3,
                  IntegerSet: $5,
                  Expression: $8,
              },
          }
      }
    | _FOR_ for_expression _OF_ string_set ':' '(' boolean_expression ')'
      {
          $$ = data.BooleanExpressionTerm{
              ForOfExpression: &data.ForOfExpression {
                  ForExpression: $2,
                  StringSet: $4,
                  Expression: $7,
              },
          }
      }
    | for_expression _OF_ string_set
      {
          $$ = data.BooleanExpressionTerm{
              ForOfExpression: &data.ForOfExpression {
                  ForExpression: $1,
                  StringSet: $3,
              },
          }
      }
    | _NOT_ boolean_expression
      {
          $$ = data.BooleanExpressionTerm{
              NotExpression: &$2,
          }
      }
    | boolean_expression _AND_ boolean_expression
      {
          and := createAndExpression($1, $3)
          $$ = data.BooleanExpressionTerm{
              AndExpression: &and,
          }
      }
    | boolean_expression _OR_ boolean_expression
      {
          or := createOrExpression($1, $3)
          $$ = data.BooleanExpressionTerm{
              OrExpression: &or,
          }
      }
    | primary_expression _LT_ primary_expression
      {
          $$ = data.BooleanExpressionTerm{
              BinaryExpression: &data.BinaryExpression{
                  Operator: data.LtOperator,
                  Left: $1,
                  Right: $3,
              },
          }
      }
    | primary_expression _GT_ primary_expression
      {
          $$ = data.BooleanExpressionTerm{
              BinaryExpression: &data.BinaryExpression{
                  Operator: data.GtOperator,
                  Left: $1,
                  Right: $3,
              },
          }
      }
    | primary_expression _LE_ primary_expression
      {
          $$ = data.BooleanExpressionTerm{
              BinaryExpression: &data.BinaryExpression{
                  Operator: data.LeOperator,
                  Left: $1,
                  Right: $3,
              },
          }
      }
    | primary_expression _GE_ primary_expression
      {
          $$ = data.BooleanExpressionTerm{
              BinaryExpression: &data.BinaryExpression{
                  Operator: data.GeOperator,
                  Left: $1,
                  Right: $3,
              },
          }
      }
    | primary_expression _EQ_ primary_expression
      {
          $$ = data.BooleanExpressionTerm{
              BinaryExpression: &data.BinaryExpression{
                  Operator: data.EqOperator,
                  Left: $1,
                  Right: $3,
              },
          }
      }
    | primary_expression _NEQ_ primary_expression
      {
          $$ = data.BooleanExpressionTerm{
              BinaryExpression: &data.BinaryExpression{
                  Operator: data.NeqOperator,
                  Left: $1,
                  Right: $3,
              },
          }
      }
    | primary_expression
      {
           $$ =  data.BooleanExpressionTerm { PrimaryExpression: $1 }
      }
    |'(' expression ')'
      {
          $$ = $2
      }
    ;


integer_set
    : '(' integer_enumeration ')'
      {
          $$  = data.IntegerSet{ IntegerEnumeration: $2 }
      }
    | range
      {
          $$ = data.IntegerSet{ Range: &$1 }
      }
    ;


range
    : '(' primary_expression _DOT_DOT_  primary_expression ')'
      {
          $$ = data.Range{
              Start: $2,
              End: $4,
          }
      }
    ;


integer_enumeration
    : primary_expression { $$ = []data.PrimaryExpression{$1} }
    | integer_enumeration ',' primary_expression {
          $$ = append($1, $3)
      }
   ;


string_set
    : '(' string_enumeration ')'
      {
          $$ = data.StringSet{ StringEnumeration: $2 }
      }
    | _THEM_
      {
          $$ = data.StringSet { Keyword: data.ThemKeyword }
      }
    ;


string_enumeration
    : string_enumeration_item { $$ = []data.StringEnumerationItem{$1} }
    | string_enumeration ',' string_enumeration_item
      {
          $$ = append($1, $3)
      }
    ;


string_enumeration_item
    : _STRING_IDENTIFIER_
      {
        $$ = data.StringEnumerationItem{
            StringIdentifier: $1,
            HasWildcard: false,
        }
      }
    | _STRING_IDENTIFIER_WITH_WILDCARD_
      {
        $$ = data.StringEnumerationItem{
            StringIdentifier: $1,
            HasWildcard: true,
        }
      }
    ;


for_expression
    : primary_expression
      {
          $$ = data.ForExpression{ PrimaryExpression: $1 }
      }
    | _ALL_
      {
          $$ = data.ForExpression { Keyword: data.AllKeyword }
      }
    | _ANY_
      {
          $$ = data.ForExpression { Keyword: data.AnyKeyword }
      }
    ;


primary_expression
    : '(' primary_expression ')'
      {
          $$ = $2
      }
    | _FILESIZE_
      {
          $$ = data.FilesizeKeyword
      }
    | _ENTRYPOINT_
      {
          $$ = data.EntrypointKeyword
      }
    | _INTEGER_FUNCTION_ '(' primary_expression ')'
      {
          $$ = data.BinaryPrimaryExpression{
              Operator: data.IntegerFunctionOperator,
              Left: $1,
              Right: $3,
          }
      }
    | _NUMBER_
      {
          $$ = $1
      }
    | _DOUBLE_
      {
          $$ = $1
      }
    | _TEXT_STRING_
      {
          $$ = $1
      }
    | _STRING_COUNT_
      {
          $$ = data.StringCount{ StringIdentifier: $1 }
      }
    | _STRING_OFFSET_ '[' primary_expression ']'
      {
          $$ = data.StringOffset{
              StringIdentifier: $1,
              Index: $3,
          }
      }
    | _STRING_OFFSET_
      {
          $$ = data.StringOffset{
              StringIdentifier: $1,
          }
      }
    | _STRING_LENGTH_ '[' primary_expression ']'
      {
          $$ = data.StringLength{
              StringIdentifier: $1,
              Index: $3,
          }
      }
    | _STRING_LENGTH_
      {
          $$ = data.StringLength{
              StringIdentifier: $1,
          }
      }
    | identifier
      {
          $$ = $1
      }
    | '-' primary_expression %prec UNARY_MINUS
      {
          $$ = data.BinaryPrimaryExpression{
              Operator: data.UnaryMinusOperator,
              Left: $2,
          }
      }
    | primary_expression '+' primary_expression
      {
          $$ = data.BinaryPrimaryExpression{
              Operator: data.PlusOperator,
              Left: $1,
              Right: $3,
          }
      }
    | primary_expression '-' primary_expression
      {
          $$ = data.BinaryPrimaryExpression{
              Operator: data.MinusOperator,
              Left: $1,
              Right: $3,
          }
      }
    | primary_expression '*' primary_expression
      {
          $$ = data.BinaryPrimaryExpression{
              Operator: data.TimesOperator,
              Left: $1,
              Right: $3,
          }
      }
    | primary_expression '\\' primary_expression
      {
          $$ = data.BinaryPrimaryExpression{
              Operator: data.DivOperator,
              Left: $1,
              Right: $3,
          }
      }
    | primary_expression '%' primary_expression
      {
          $$ = data.BinaryPrimaryExpression{
              Operator: data.ModOperator,
              Left: $1,
              Right: $3,
          }
      }
    | primary_expression '^' primary_expression
      {
          $$ = data.BinaryPrimaryExpression{
              Operator: data.XorOperator,
              Left: $1,
              Right: $3,
          }
      }
    | primary_expression '&' primary_expression
      {
          $$ = data.BinaryPrimaryExpression{
              Operator: data.BitwiseAndOperator,
              Left: $1,
              Right: $3,
          }
      }
    | primary_expression '|' primary_expression
      {
          $$ = data.BinaryPrimaryExpression{
              Operator: data.BitwiseOrOperator,
              Left: $1,
              Right: $3,
          }
      }
    | '~' primary_expression
      {
          $$ = data.BinaryPrimaryExpression{
              Operator: data.BitwiseNotOperator,
              Left: $2,
          }
      }
    | primary_expression _SHIFT_LEFT_ primary_expression
      {
          $$ = data.BinaryPrimaryExpression{
              Operator: data.ShiftLeftOperator,
              Left: $1,
              Right: $3,
          }
      }
    | primary_expression _SHIFT_RIGHT_ primary_expression
      {
          $$ = data.BinaryPrimaryExpression{
              Operator: data.ShiftRightOperator,
              Left: $1,
              Right: $3,
          }
      }
    | regexp
      {
          $$ = $1
      }
    ;

%%

func createOrExpression(terms ...data.BooleanExpressionTerm) (or data.OrExpression) {
    for _, term := range terms {
        if term.OrExpression == nil {
           or = append(or, term)
        } else {
           or = append(or, *term.OrExpression...)
        }
    }

    return
}

func createAndExpression(terms ...data.BooleanExpressionTerm) (and data.AndExpression) {
    for _, term := range terms {
        if term.AndExpression == nil {
           and = append(and, term)
        } else {
           and = append(and, *term.AndExpression...)
        }
    }

    return
}
