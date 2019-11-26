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
    "github.com/VirusTotal/gyp/pb"
    "github.com/VirusTotal/gyp/ast"
    "github.com/VirusTotal/gyp/error"
)


type ruleModifiers struct {
  Global bool
  Private bool
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
%type <rule>      rule
%type <ss>        tags
%type <ss>        tag_list
%type <meta>      meta_declaration
%type <metas>     meta_declarations
%type <metas>     meta
%type <yss>       strings
%type <ys>        string_declaration
%type <yss>       string_declarations
%type <mod>       string_modifier
%type <mod>       string_modifiers
%type <mod>       regexp_modifier
%type <mod>       regexp_modifiers
%type <mod>       hex_modifier
%type <mod>       hex_modifiers
%type <rm>        rule_modifier
%type <rm>        rule_modifiers
%type <node>      condition
%type <node>      boolean_expression
%type <node>      expression
%type <node>      primary_expression
%type <id>        identifier
%type <exprs>     arguments_list
%type <exprs>     arguments
%type <regp>      regexp
%type <node>      for_expression
%type <ss>        for_variables
%type <node>      integer_set
%type <intenum>   integer_enumeration
%type <rng>       range
%type <node>      string_set
%type <strenum>   string_enumeration
%type <strenumi>  string_enumeration_item
%type <iterator>  iterator

%union {
    i64           int64
    f64           float64
    s             string
    ss            []string

    hextokens     *pb.HexTokens
    rm            *ruleModifiers
    rule          *ast.Rule
    meta          *ast.Meta
    metas         []*ast.Meta
    node          ast.Node
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
      }
    | rules _END_OF_INCLUDED_FILE_
      {

      }
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
        lexer := asLexer(yrlex)

        // Forbid duplicate rules
        for _, r := range  lexer.ruleSet.Rules {
            if $3 == r.Identifier {
              return lexer.SetError(
                gyperror.DuplicateRuleError, `duplicate rule "%s"`, $3)
            }
        }

        $$ = &ast.Rule{
            Global: $1.Global,
            Private: $1.Private,
            Identifier: $3,
        }
      }
      tags '{' meta strings
      {
        $<rule>4.Tags = $5
        $<rule>4.Meta = $7
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

      }
    | _STRINGS_ ':' string_declarations
      {

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
        $$ = &ruleModifiers{}
      }
    | rule_modifiers rule_modifier
      {
        $1.Global = $1.Global || $2.Global
        $1.Private = $1.Private || $2.Private
        $$ = $1
      }
    ;


rule_modifier
    : _PRIVATE_
      {
        $$ = &ruleModifiers{Private: true}
      }
    | _GLOBAL_
      {
        $$ = &ruleModifiers{Global: true}
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
            return lexer.SetError(
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
      }
    | string_declarations string_declaration
      {

      }
    ;


string_declaration
    : _STRING_IDENTIFIER_ '='
      {
      }
      _TEXT_STRING_ string_modifiers
      {

      }
    | _STRING_IDENTIFIER_ '='
      {

      }
      _REGEXP_ regexp_modifiers
      {

      }
    | _STRING_IDENTIFIER_ '=' _HEX_STRING_ hex_modifiers
      {

      }
    ;


string_modifiers
    : /* empty */
      {
      }
    | string_modifiers string_modifier
      {
      }
    ;


string_modifier
    : _WIDE_        { }
    | _ASCII_       { }
    | _NOCASE_      { }
    | _FULLWORD_    { }
    | _PRIVATE_     { }
    | _XOR_
      {

      }
    | _XOR_ '(' _NUMBER_ ')'
      {

      }
    | _XOR_ '(' _NUMBER_ '-' _NUMBER_ ')'
      {
        lexer := asLexer(yrlex)

        if $3 < 0 {
          return lexer.SetError(
            gyperror.InvalidStringModifierError,
            "lower bound for xor range exceeded (min: 0)")
        }

        if $5 > 255 {
          return lexer.SetError(
            gyperror.InvalidStringModifierError,
            "upper bound for xor range exceeded (max: 255)")
        }

        if $3 > $5 {
          return lexer.SetError(
            gyperror.InvalidStringModifierError,
            "xor lower bound exceeds upper bound")
        }
      }
    ;


regexp_modifiers
    : /* empty */
      {

      }
    | regexp_modifiers regexp_modifier
      {

      }
    ;


regexp_modifier
    : _WIDE_        { }
    | _ASCII_       { }
    | _NOCASE_      {  }
    | _FULLWORD_    {  }
    | _PRIVATE_     {  }
    ;


hex_modifiers
    : /* empty */
      {

      }
    | hex_modifiers hex_modifier
      {

      }
    ;


hex_modifier
    : _PRIVATE_
      {

      }
    ;


identifier
    : _IDENTIFIER_
      {

      }
    | identifier '.' _IDENTIFIER_
      {

      }
    | identifier '[' primary_expression ']'
      {

      }
    | identifier '(' arguments ')'
      {

      }
    ;


arguments
    : /* empty */
      {

      }
    | arguments_list
     {

     }


arguments_list
    : expression
      {

      }
    | arguments_list ',' expression
      {
      }
    ;


regexp
    : _REGEXP_
    {

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

      }
    | primary_expression _CONTAINS_ primary_expression
      {

      }
    | _STRING_IDENTIFIER_
      {

      }
    | _STRING_IDENTIFIER_ _AT_ primary_expression
      {

      }
    | _STRING_IDENTIFIER_ _IN_ range
      {

      }
    | _FOR_ for_expression error { }
    | _FOR_ for_expression for_variables _IN_ iterator ':' '(' boolean_expression ')'
      {

      }
    | _FOR_ for_expression _OF_ string_set ':' '(' boolean_expression ')'
      {

      }
    | for_expression _OF_ string_set
      {

      }
    | _NOT_ boolean_expression
      {
        $$ = &ast.Not{$2}
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
          Operands: []ast.Node{$1, $3},
        }
      }
    | primary_expression _GT_ primary_expression
      {
        $$ = &ast.Operation{
          Operator: ast.OpGreaterThan,
          Operands: []ast.Node{$1, $3},
        }
      }
    | primary_expression _LE_ primary_expression
      {
        $$ = &ast.Operation{
          Operator: ast.OpLessOrEqual,
          Operands: []ast.Node{$1, $3},
        }
      }
    | primary_expression _GE_ primary_expression
      {
        $$ = &ast.Operation{
          Operator: ast.OpGreaterOrEqual,
          Operands: []ast.Node{$1, $3},
        }
      }
    | primary_expression _EQ_ primary_expression
      {
        $$ = &ast.Operation{
          Operator: ast.OpEqual,
          Operands: []ast.Node{$1, $3},
        }
      }
    | primary_expression _NEQ_ primary_expression
      {
        $$ = &ast.Operation{
          Operator: ast.OpNotEqual,
          Operands: []ast.Node{$1, $3},
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

      }
    | range
      {

      }
    ;


range
    : '(' primary_expression _DOT_DOT_  primary_expression ')'
      {

      }
    ;


integer_enumeration
    : primary_expression
      {

      }
    | integer_enumeration ',' primary_expression
      {
      }
   ;


string_set
    : '(' string_enumeration ')'
      {
      }
    | _THEM_
      {
        $$ = ast.KeywordThem
      }
    ;


string_enumeration
    : string_enumeration_item
      {

      }
    | string_enumeration ',' string_enumeration_item
      {
      }
    ;


string_enumeration_item
    : _STRING_IDENTIFIER_
      {

      }
    | _STRING_IDENTIFIER_WITH_WILDCARD_
      {

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
    ;


for_variables
    : _IDENTIFIER_
      {

      }
    | for_variables ',' _IDENTIFIER_
      {

      }
    ;

iterator
    : identifier
      {

      }
    | integer_set
      {

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
        $$ = &ast.LiteralString{$1}
      }
    | _STRING_COUNT_
      {

      }
    | _STRING_OFFSET_ '[' primary_expression ']'
      {

      }
    | _STRING_OFFSET_
      {

      }
    | _STRING_LENGTH_ '[' primary_expression ']'
      {

      }
    | _STRING_LENGTH_
      {

      }
    | identifier
      {

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

      }
    ;

%%


// This function takes an operator and two operands and returns a node
// representing the operation. If the left operand is an operation of the
// the same kind than the specified by the operator, the right operand is
// simply appended to that existing operation. This implies that the operator
// must be left-associative in order to be used with this function.
func operation(operator ast.OperatorType, left, right ast.Node) (n ast.Node) {
  if operation, ok := left.(*ast.Operation); ok && operation.Operator == operator {
    operation.Operands = append(operation.Operands, right)
    n = operation
  } else {
    n = &ast.Operation{
      Operator: operator,
      Operands: []ast.Node{left, right},
    }
  }
  return n
}


// Strings in YARA rules may contain escaped chars, such as doublequotes (")
// or new lines (\n).
// The strings returned by the lexer contains the backslashes used to escape
// those chars. However, the backslashes are not part of the string to match
// and they should be removed.
// Example:
// -  YARA rule:                  $str = "First line\nSecond line"
// -  decodeEscapedString input:  str  = "First line\\nSecond line"
// -  decodeEscapedString output: out  = "First line\nSecond line"
func decodeEscapedString(str string) (out string) {
  if _, err := fmt.Sscanf(fmt.Sprintf("\"%s\"", str), "%q", &out); err != nil {
    panic(err)
  }

  return out
}
