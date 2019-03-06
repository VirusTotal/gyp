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
package gyp

import (
    "fmt"
    proto "github.com/golang/protobuf/proto"

    "github.com/VirusTotal/gyp/ast"
    "github.com/VirusTotal/gyp/error"
)

var ParsedRuleset ast.RuleSet

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
%token <hextokens> _HEX_STRING_
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

%type <s>         import
%type <yr>        rule
%type <ss>        tags
%type <ss>        tag_list
%type <m>         meta
%type <mp>        meta_declaration
%type <m>         meta_declarations
%type <yss>       strings
%type <ys>        string_declaration
%type <yss>       string_declarations
%type <mod>       string_modifier
%type <mod>       string_modifiers
%type <rm>        rule_modifier
%type <rm>        rule_modifiers
%type <expr>      condition
%type <expr>      boolean_expression
%type <expr>      expression
%type <expr>      primary_expression
%type <id>        identifier
%type <exprs>     arguments_list
%type <exprs>     arguments
%type <regp>      regexp
%type <forexp>    for_expression
%type <intset>    integer_set
%type <intenum>   integer_enumeration
%type <rng>       range
%type <strset>    string_set
%type <strenum>   string_enumeration
%type <strenumi>  string_enumeration_item

%union {
    i64           int64
    f64           float64
    s             string
    ss            []string

    rm            *ast.RuleModifiers
    m             []*ast.Meta
    mp            *ast.Meta
    mod           *ast.StringModifiers
    reg           ast.Regexp
    regp          *ast.Regexp
    ys            *ast.String
    yss           []*ast.String
    yr            *ast.Rule
    id            *ast.Identifier
    forexp        *ast.ForExpression
    intset        *ast.IntegerSet
    intenum       *ast.IntegerEnumeration
    rng           *ast.Range
    strset        *ast.StringSet
    strenumi      *ast.StringEnumeration_StringEnumerationItem
    strenum       *ast.StringEnumeration
    expr          *ast.Expression
    exprs         *ast.Expressions
    hextokens     *ast.HexTokens
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
          $$ = &ast.Rule{
              Modifiers: $1,
              Identifier: proto.String($3),
          }

          // Forbid duplicate rules
          for _, r := range ParsedRuleset.Rules {
              if $3 == *r.Identifier {
                  err := gyperror.Error{ gyperror.DuplicateRuleError, $3 }
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
                  err := gyperror.Error{
                    gyperror.DuplicateTagError,
                    fmt.Sprintf(
                      `"%s" at rule "%s"`,
                      $<yr>4.GetIdentifier(),
                      t),
                  }
                  panic(err)
              }
              idx[t] = struct{}{}
          }

          $<yr>4.Meta = $7

          $<yr>4.Strings = $8

          // Forbid duplicate string IDs, except `$` (anonymous)
          idx = make(map[string]struct{})
          for _, s := range $8 {
              if s.GetId() == "$" {
                  continue
              }
              if _, had := idx[*s.Id]; had {
                  err := gyperror.Error{
                    gyperror.DuplicateStringError,
                    fmt.Sprintf(
                      `"%s" at rule "%s"`,
                      $<yr>4.GetIdentifier(),
                      s.GetId(),
                    ),
                  }
                  panic(err)
              }
              idx[*s.Id] = struct{}{}
          }
      }
      condition _RBRACE_
      {
          condition := $10
          $<yr>4.Condition = condition
          $$ = $<yr>4
      }
    ;


meta
    : /* empty */ { $$ = []*ast.Meta{} }
    | _META_ ':' meta_declarations
      {
          $$ = make([]*ast.Meta, 0, len($3))
          for _, mpair := range $3 {
              // YARA is ok with duplicate keys; we follow suit
              $$ = append($$, mpair)
          }
      }
    ;


strings
    : /* empty */ { $$ = []*ast.String{} }
    | _STRINGS_ ':' string_declarations { $$ = $3 }
    ;


condition
    : _CONDITION_ ':' boolean_expression { $$ = $3 }
    ;


rule_modifiers
    : /* empty */ { $$ = &ast.RuleModifiers{} }
    | rule_modifiers rule_modifier     {
        $$ = &ast.RuleModifiers{
            Private: proto.Bool($1.GetPrivate() || $2.GetPrivate()),
            Global: proto.Bool($1.GetGlobal() || $2.GetGlobal()),
        }
    }
    ;


rule_modifier
    : _PRIVATE_ { $$ = &ast.RuleModifiers{ Private: proto.Bool(true) } }
    | _GLOBAL_ { $$ = &ast.RuleModifiers{ Global: proto.Bool(true) } }
    ;


tags
    : /* empty */ { $$ = []string{} }
    | ':' tag_list { $$ = $2 }
    ;


tag_list
    : _IDENTIFIER_ { $$ = []string{$1} }
    | tag_list _IDENTIFIER_ { $$ = append($1, $2) }
    ;


meta_declarations
    : meta_declaration { $$ = []*ast.Meta{$1} }
    | meta_declarations meta_declaration { $$ = append($$, $2) }
    ;


meta_declaration
    : _IDENTIFIER_ '=' _TEXT_STRING_
      {
          $$ = &ast.Meta{
              Key: proto.String($1),
              Value: &ast.Meta_Text{$3},
          }
      }
    | _IDENTIFIER_ '=' _NUMBER_
      {
          $$ = &ast.Meta{
              Key: proto.String($1),
              Value: &ast.Meta_Number{$3},
          }
      }
    | _IDENTIFIER_ '=' '-' _NUMBER_
      {
          $$ = &ast.Meta{
              Key: proto.String($1),
              Value: &ast.Meta_Number{-$4},
          }
      }
    | _IDENTIFIER_ '=' _TRUE_
      {
          $$ = &ast.Meta{
              Key: proto.String($1),
              Value: &ast.Meta_Boolean{true},
          }
      }
    | _IDENTIFIER_ '=' _FALSE_
      {
          $$ = &ast.Meta{
              Key: proto.String($1),
              Value: &ast.Meta_Boolean{false},
          }
      }
    ;


string_declarations
    : string_declaration { $$ = []*ast.String{$1} }
    | string_declarations string_declaration { $$ = append($1, $2) }
    ;


string_declaration
    : _STRING_IDENTIFIER_ '='
      {
          $$ = &ast.String{
              Id: proto.String($1),
          }
      }
      _TEXT_STRING_ string_modifiers
      {
          $<ys>3.Value = &ast.String_Text{&ast.TextString{
            Text: proto.String($4),
            Modifiers: $5 ,
          }}
          $$ = $<ys>3
      }
    | _STRING_IDENTIFIER_ '='
      {
          $$ = &ast.String{
              Id: proto.String($1),
          }
      }
      _REGEXP_ string_modifiers
      {
          $<ys>3.Value = &ast.String_Regexp{&ast.Regexp{
              Text: $4.Text,
          }}

          $5.I = $4.Modifiers.I
          $5.S = $4.Modifiers.S

          $<ys>3.GetRegexp().Modifiers = $5

          $$ = $<ys>3
      }
    | _STRING_IDENTIFIER_ '=' _HEX_STRING_
      {
          $$ = &ast.String{
              Id: proto.String($1),
              Value: &ast.String_Hex{$3},
          }
      }
    ;


string_modifiers
    : /* empty */                         { $$ = &ast.StringModifiers{} }
    | string_modifiers string_modifier
      {
          $$ = &ast.StringModifiers {
              Wide: proto.Bool($1.GetWide() || $2.GetWide()),
              Ascii: proto.Bool($1.GetAscii() || $2.GetAscii()),
              Nocase: proto.Bool($1.GetNocase() || $2.GetNocase()),
              Fullword: proto.Bool($1.GetFullword() || $2.GetFullword()),
              Xor: proto.Bool($1.GetXor() || $2.GetXor()),
          }
      }
    ;


string_modifier
    : _WIDE_        { $$ = &ast.StringModifiers{ Wide: proto.Bool(true) } }
    | _ASCII_       { $$ = &ast.StringModifiers{ Ascii: proto.Bool(true) } }
    | _NOCASE_      { $$ = &ast.StringModifiers{ Nocase: proto.Bool(true)} }
    | _FULLWORD_    { $$ = &ast.StringModifiers{ Fullword: proto.Bool(true) } }
    | _XOR_         { $$ = &ast.StringModifiers{ Xor: proto.Bool(true) } }
    ;



identifier
    : _IDENTIFIER_
      {
          $$ = &ast.Identifier{
              Items: []*ast.Identifier_IdentifierItem{
                  { Item: &ast.Identifier_IdentifierItem_Identifier{$1} },
              },
          }
      }
    | identifier '.' _IDENTIFIER_
      {
          $$.Items =  append(
              $1.Items,
              &ast.Identifier_IdentifierItem{
                  Item: &ast.Identifier_IdentifierItem_Identifier{$3},
              },
          )
      }
    | identifier '[' primary_expression ']'
      {
          $$.Items = append(
              $1.Items,
              &ast.Identifier_IdentifierItem{
                 Item: &ast.Identifier_IdentifierItem_Index{$3},
              },
          )
      }
    | identifier '(' arguments ')'
      {
          $$.Items = append(
              $1.Items,
              &ast.Identifier_IdentifierItem{
                  Item: &ast.Identifier_IdentifierItem_Arguments{$3},
              },
          )
      }
    ;


arguments
    : /* empty */     { $$ = &ast.Expressions{} }
    | arguments_list  { $$ = $1 }


arguments_list
    : expression
      {
          $$ = &ast.Expressions{
              Terms: []*ast.Expression{$1},
          }
      }
    | arguments_list ',' expression
      {
          $$.Terms = append($1.Terms, $3)
      }
    ;


regexp
    : _REGEXP_
    {
        regexp := $1
        $$ = &regexp
    }
    ;


boolean_expression
    : expression { $$ = $1 }
    ;

expression
    : _TRUE_
      {
          $$ = &ast.Expression{
             Expression: &ast.Expression_BoolValue{true},
          }
      }
    | _FALSE_
      {
          $$ = &ast.Expression{
             Expression: &ast.Expression_BoolValue{false},
          }
      }
    | primary_expression _MATCHES_ regexp
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_BinaryExpression{
                  BinaryExpression: &ast.BinaryExpression{
                      Operator: ast.BinaryExpression_MATCHES.Enum(),
                      Left: $1,
                      Right: &ast.Expression{
                          Expression: &ast.Expression_Regexp{$3},
                      },
                  },
              },
          }
      }
    | primary_expression _CONTAINS_ primary_expression
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_BinaryExpression{
                  BinaryExpression: &ast.BinaryExpression{
                      Operator: ast.BinaryExpression_CONTAINS.Enum(),
                      Left: $1,
                      Right: $3,
                  },
              },
          }
      }
    | _STRING_IDENTIFIER_
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_StringIdentifier{$1},
          }
      }
    | _STRING_IDENTIFIER_ _AT_ primary_expression
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_BinaryExpression{
                  BinaryExpression: &ast.BinaryExpression{
                      Operator: ast.BinaryExpression_AT.Enum(),
                      Left: &ast.Expression{
                          Expression: &ast.Expression_StringIdentifier{$1},
                      },
                      Right: $3,
                  },
              },
          }
      }
    | _STRING_IDENTIFIER_ _IN_ range
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_BinaryExpression{
                  BinaryExpression: &ast.BinaryExpression{
                      Operator: ast.BinaryExpression_IN.Enum(),
                      Left: &ast.Expression{
                          Expression: &ast.Expression_StringIdentifier{$1},
                      },
                      Right: &ast.Expression{
                          Expression: &ast.Expression_Range{$3},
                      },
                  },
              },
          }
      }
    | _FOR_ for_expression error { }
    | _FOR_ for_expression _IDENTIFIER_ _IN_ integer_set ':' '(' boolean_expression ')'
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_ForInExpression{
                  ForInExpression: &ast.ForInExpression{
                      ForExpression: $2,
                      Identifier: proto.String($3),
                      IntegerSet: $5,
                      Expression: $8,
                  },
              },
          }
      }
    | _FOR_ for_expression _OF_ string_set ':' '(' boolean_expression ')'
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_ForOfExpression{
                  ForOfExpression: &ast.ForOfExpression{
                      ForExpression: $2,
                      StringSet: $4,
                      Expression: $7,
                  },
              },
          }
      }
    | for_expression _OF_ string_set
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_ForOfExpression{
                  ForOfExpression: &ast.ForOfExpression{
                      ForExpression: $1,
                      StringSet: $3,
                  },
              },
          }
      }
    | _NOT_ boolean_expression
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_NotExpression{$2},
          }
      }
    | boolean_expression _AND_ boolean_expression
      {
          $$ = createAndExpression($1, $3)
      }
    | boolean_expression _OR_ boolean_expression
      {
          $$ = createOrExpression($1, $3)
      }
    | primary_expression _LT_ primary_expression
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_BinaryExpression{
                  BinaryExpression: &ast.BinaryExpression{
                      Operator: ast.BinaryExpression_LT.Enum(),
                      Left: $1,
                      Right: $3,
                  },
              },
          }
      }
    | primary_expression _GT_ primary_expression
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_BinaryExpression{
                  BinaryExpression: &ast.BinaryExpression{
                      Operator: ast.BinaryExpression_GT.Enum(),
                      Left: $1,
                      Right: $3,
                  },
              },
          }
      }
    | primary_expression _LE_ primary_expression
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_BinaryExpression{
                  BinaryExpression: &ast.BinaryExpression{
                      Operator: ast.BinaryExpression_LE.Enum(),
                      Left: $1,
                      Right: $3,
                  },
              },
          }
      }
    | primary_expression _GE_ primary_expression
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_BinaryExpression{
                  BinaryExpression: &ast.BinaryExpression{
                      Operator: ast.BinaryExpression_GE.Enum(),
                      Left: $1,
                      Right: $3,
                  },
              },
          }
      }
    | primary_expression _EQ_ primary_expression
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_BinaryExpression{
                  BinaryExpression: &ast.BinaryExpression{
                      Operator: ast.BinaryExpression_EQ.Enum(),
                      Left: $1,
                      Right: $3,
                  },
              },
          }
      }
    | primary_expression _NEQ_ primary_expression
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_BinaryExpression{
                  BinaryExpression: &ast.BinaryExpression{
                      Operator: ast.BinaryExpression_NEQ.Enum(),
                      Left: $1,
                      Right: $3,
                  },
              },
          }
      }
    | primary_expression
      {
          $$ = $1
      }
    |'(' expression ')'
      {
          $$ = $2
      }
    ;


integer_set
    : '(' integer_enumeration ')'
      {
          $$ = &ast.IntegerSet{
              Set: &ast.IntegerSet_IntegerEnumeration{$2},
          }
      }
    | range
      {
          $$ = &ast.IntegerSet{
              Set: &ast.IntegerSet_Range{$1},
          }
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
          $$ = &ast.IntegerEnumeration{
              Values: []*ast.Expression{$1},
          }
      }
    | integer_enumeration ',' primary_expression {
          $$.Values = append($$.Values, $3)
      }
   ;


string_set
    : '(' string_enumeration ')'
      {
          $$ = &ast.StringSet{ Set: &ast.StringSet_Strings{$2} }
      }
    | _THEM_
      {
          $$ = &ast.StringSet { Set: &ast.StringSet_Keyword{ast.StringSetKeyword_THEM} }
      }
    ;


string_enumeration
    : string_enumeration_item
      {
          $$ = &ast.StringEnumeration{
              Items: []*ast.StringEnumeration_StringEnumerationItem{$1},
          }
      }
    | string_enumeration ',' string_enumeration_item
      {
          $$.Items = append($1.Items, $3)
      }
    ;


string_enumeration_item
    : _STRING_IDENTIFIER_
      {
        $$ = &ast.StringEnumeration_StringEnumerationItem{
            StringIdentifier: proto.String($1),
            HasWildcard: proto.Bool(false),
        }
      }
    | _STRING_IDENTIFIER_WITH_WILDCARD_
      {
        $$ = &ast.StringEnumeration_StringEnumerationItem{
            StringIdentifier: proto.String($1),
            HasWildcard: proto.Bool(true),
        }
      }
    ;


for_expression
    : primary_expression
      {
          $$ = &ast.ForExpression{
              For: &ast.ForExpression_Expression{$1},
          }
      }
    | _ALL_
      {
          $$ = &ast.ForExpression{
              For: &ast.ForExpression_Keyword{ast.ForKeyword_ALL},
          }
      }
    | _ANY_
      {
          $$ = &ast.ForExpression{
              For: &ast.ForExpression_Keyword{ast.ForKeyword_ANY},
          }
      }
    ;


primary_expression
    : '(' primary_expression ')'
      {
          $$ = $2
      }
    | _FILESIZE_
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_Keyword{ast.Keyword_FILESIZE},
          }
      }
    | _ENTRYPOINT_
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_Keyword{ast.Keyword_ENTRYPOINT},
          }
      }
    | _INTEGER_FUNCTION_ '(' primary_expression ')'
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_IntegerFunction{
                  &ast.IntegerFunction{
                      Function: proto.String($1),
                      Argument: $3,
                  },
              },
          }
      }
    | _NUMBER_
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_NumberValue{$1},
          }
      }
    | _DOUBLE_
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_DoubleValue{$1},
          }
      }
    | _TEXT_STRING_
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_Text{$1},
          }
      }
    | _STRING_COUNT_
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_StringCount{$1},
          }
      }
    | _STRING_OFFSET_ '[' primary_expression ']'
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_StringOffset{
                  &ast.StringOffset{
                      StringIdentifier: proto.String($1),
                      Index: $3,
                  },
              },
          }
      }
    | _STRING_OFFSET_
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_StringOffset{
                  &ast.StringOffset{
                      StringIdentifier: proto.String($1),
                  },
              },
          }
      }
    | _STRING_LENGTH_ '[' primary_expression ']'
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_StringLength{
                  &ast.StringLength{
                      StringIdentifier: proto.String($1),
                      Index: $3,
                  },
              },
          }
      }
    | _STRING_LENGTH_
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_StringLength{
                  &ast.StringLength{
                      StringIdentifier: proto.String($1),
                  },
              },
          }
      }
    | identifier
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_Identifier{$1},
          }
      }
    | '-' primary_expression %prec UNARY_MINUS
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_UnaryExpression{
                  &ast.UnaryExpression{
                      Operator: ast.UnaryExpression_UNARY_MINUS.Enum(),
                      Expression: $2,
                  },
              },
          }
      }
    | primary_expression '+' primary_expression
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_BinaryExpression{
                  BinaryExpression: &ast.BinaryExpression{
                      Operator: ast.BinaryExpression_PLUS.Enum(),
                      Left: $1,
                      Right: $3,
                  },
              },
          }
      }
    | primary_expression '-' primary_expression
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_BinaryExpression{
                  BinaryExpression: &ast.BinaryExpression{
                      Operator: ast.BinaryExpression_MINUS.Enum(),
                      Left: $1,
                      Right: $3,
                  },
              },
          }
      }
    | primary_expression '*' primary_expression
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_BinaryExpression{
                  BinaryExpression: &ast.BinaryExpression{
                      Operator: ast.BinaryExpression_TIMES.Enum(),
                      Left: $1,
                      Right: $3,
                  },
              },
          }
      }
    | primary_expression '\\' primary_expression
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_BinaryExpression{
                  BinaryExpression: &ast.BinaryExpression{
                      Operator: ast.BinaryExpression_DIV.Enum(),
                      Left: $1,
                      Right: $3,
                  },
              },
          }
      }
    | primary_expression '%' primary_expression
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_BinaryExpression{
                  BinaryExpression: &ast.BinaryExpression{
                      Operator: ast.BinaryExpression_MOD.Enum(),
                      Left: $1,
                      Right: $3,
                  },
              },
          }
      }
    | primary_expression '^' primary_expression
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_BinaryExpression{
                  BinaryExpression: &ast.BinaryExpression{
                      Operator: ast.BinaryExpression_XOR.Enum(),
                      Left: $1,
                      Right: $3,
                  },
              },
          }
      }
    | primary_expression '&' primary_expression
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_BinaryExpression{
                  BinaryExpression: &ast.BinaryExpression{
                      Operator: ast.BinaryExpression_BITWISE_AND.Enum(),
                      Left: $1,
                      Right: $3,
                  },
              },
          }
      }
    | primary_expression '|' primary_expression
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_BinaryExpression{
                  BinaryExpression: &ast.BinaryExpression{
                      Operator: ast.BinaryExpression_BITWISE_OR.Enum(),
                      Left: $1,
                      Right: $3,
                  },
              },
          }
      }
    | '~' primary_expression
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_UnaryExpression{
                  UnaryExpression: &ast.UnaryExpression{
                      Operator: ast.UnaryExpression_BITWISE_NOT.Enum(),
                      Expression: $2,
                  },
              },
          }
      }
    | primary_expression _SHIFT_LEFT_ primary_expression
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_BinaryExpression{
                  BinaryExpression: &ast.BinaryExpression{
                      Operator: ast.BinaryExpression_SHIFT_LEFT.Enum(),
                      Left: $1,
                      Right: $3,
                  },
              },
          }
      }
    | primary_expression _SHIFT_RIGHT_ primary_expression
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_BinaryExpression{
                  BinaryExpression: &ast.BinaryExpression{
                      Operator: ast.BinaryExpression_SHIFT_RIGHT.Enum(),
                      Left: $1,
                      Right: $3,
                  },
              },
          }
      }
    | regexp
      {
          $$ = &ast.Expression{
              Expression: &ast.Expression_Regexp{$1},
          }
      }
    ;

%%

func createOrExpression(terms... *ast.Expression) (or *ast.Expression) {
    expressions := []*ast.Expression{}
    for _, term := range terms {
        if term.GetOrExpression() == nil {
           expressions = append(expressions, term)
        } else {
           expressions = append(expressions, term.GetOrExpression().GetTerms()...)
        }
    }

    or = &ast.Expression{
        Expression: &ast.Expression_OrExpression{&ast.Expressions{ Terms: expressions }},
    }

    return
}

func createAndExpression(terms... *ast.Expression) (and *ast.Expression) {
    expressions := []*ast.Expression{}
    for _, term := range terms {
        if term.GetAndExpression() == nil {
           expressions = append(expressions, term)
        } else {
           expressions = append(expressions, term.GetAndExpression().GetTerms()...)
        }
    }

    and = &ast.Expression{
        Expression: &ast.Expression_AndExpression{&ast.Expressions{ Terms: expressions }},
    }

    return
}
