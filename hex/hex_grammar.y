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

%{
package hex

import (
  "github.com/VirusTotal/gyp/ast"
  "github.com/VirusTotal/gyp/error"
)

const StringChainingThreshold int = 200

type byteWithMask struct {
  Value byte
  Mask byte
}

%}


%token <bm> _BYTE_
%token <bm> _MASKED_BYTE_
%token <integer> _NUMBER_
%token _LBRACE_
%token _RBRACE_
%token _LBRACKET_
$token _RBRACKET_
%token _HYPHEN_
%token _LPARENS_
%token _RPARENS_
$token _PIPE_

%type <tokens>   tokens
%type <tokens>   token_sequence
%type <token>    token_or_range
%type <token>    token
%type <hexor>    alternatives
%type <token>    range
%type <bytes>    bytes
%type <bm>       byte

%union {
  integer int
  bm      byteWithMask
  token   ast.HexToken
  tokens  ast.HexTokens
  bytes   *ast.HexBytes
  hexor   *ast.HexOr
}

%%

hex_string
    : _LBRACE_ tokens _RBRACE_
      {
        asLexer(xxlex).hexTokens = $2
      }
    ;


tokens
    : token
      {
        $$ = []ast.HexToken{$1}
      }
    | token token
      {
        $$ =[]ast.HexToken{$1, $2}
      }
    | token token_sequence token
      {
        $$ = append(append([]ast.HexToken{$1}, $2...), $3)
      }
    ;


token_sequence
    : token_or_range
      {
        $$ = []ast.HexToken{$1}
      }
    | token_sequence token_or_range
      {
        $$ = append($1, $2)
      }
    ;


token_or_range
    : token
      {
        $$ = $1
      }
    | range
      {
        $$ = $1
      }
    ;


token
    : bytes
      {
        $$ = $1
      }
    | _LPARENS_
      {
        asLexer(xxlex).insideOr += 1
      }
      alternatives _RPARENS_
      {
        asLexer(xxlex).insideOr -= 1
        $$ = $3
      }
    ;


range
    : _LBRACKET_ _NUMBER_ _RBRACKET_
      {
        lexer := asLexer(xxlex)

        if $2 <= 0 {
          return lexer.SetError(
            gyperror.InvalidJumpLengthError,
            `invalid jump length: %d`, $2)
        }

        if lexer.insideOr > 0 && $2 > StringChainingThreshold {
          return lexer.SetError(
            gyperror.JumpTooLargeInsideAlternationError,
            `jump too large inside alternation: %d`, $2)
        }

        $$ = &ast.HexJump{
          Start: $2,
          End: $2,
        }
      }
    | _LBRACKET_ _NUMBER_ _HYPHEN_ _NUMBER_ _RBRACKET_
      {
        lexer := asLexer(xxlex)

        if lexer.insideOr > 0 &&
          ($2 > StringChainingThreshold || $4 > StringChainingThreshold) {
            return lexer.SetError(
              gyperror.JumpTooLargeInsideAlternationError,
              `jump too large inside alternation: %d-%d`, $2, $4)
        }

        if $2 < 0 || $4 < 0 {
          return lexer.SetError(
            gyperror.NegativeJumpError,
            `negative jump: %d-%d`, $2, $4)
        }

        if $2 > $4 {
          return lexer.SetError(
            gyperror.InvalidJumpRangeError,
            `jump too large inside alternation: %d-%d`, $2, $4)
        }

        $$ = &ast.HexJump{
          Start: $2,
          End: $4,
        }
      }
    | _LBRACKET_ _NUMBER_ _HYPHEN_ _RBRACKET_
      {
        lexer := asLexer(xxlex)

        if lexer.insideOr > 0 {
          return lexer.SetError(
            gyperror.UnboundedJumpInsideAlternationError,
            `unbounded jump inside alternation: %d`, $2)
        }

        if $2 < 0 {
          return lexer.SetError(
            gyperror.NegativeJumpError,
            `negative jump: %d`, $2)
        }

        $$ = &ast.HexJump{
          Start: $2,
        }
      }
    | _LBRACKET_ _HYPHEN_ _RBRACKET_
      {
        lexer := asLexer(xxlex)

        if lexer.insideOr > 0 {
          return lexer.SetError(
            gyperror.UnboundedJumpInsideAlternationError,
            `unbounded jump inside alternation`)
        }

        $$ = &ast.HexJump{}
      }
    ;


alternatives
    : tokens
      {
        $$ = &ast.HexOr{
          Alternatives: ast.HexTokens{$1},
        }
      }
    | alternatives _PIPE_ tokens
      {
        $1.Alternatives = append($1.Alternatives, $3)
        $$ = $1
      }
    ;


// This production doesn't exist in the original YARA's hex grammar, because
// YARA handles each byte as an individual token. In gyp we wanted to group
// contiguous bytes into a single token, and for that reason the "bytes"
// production was introduced.
bytes
    : byte
      {
        $$ = &ast.HexBytes{
          Bytes: []byte{$1.Value},
          Masks: []byte{$1.Mask},
        }
      }
    | bytes byte
      {
        $1.Bytes = append($1.Bytes, $2.Value)
        $1.Masks = append($1.Masks, $2.Mask)
      }


byte
    : _BYTE_
      {
        $$ = $1
      }
    | _MASKED_BYTE_
      {
        $$ = $1
      }
    ;

%%
