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
  "fmt"
  proto "github.com/golang/protobuf/proto"

  "github.com/VirusTotal/go-yara-parser"
)

const StringChainingThreshold int64 = 200

var ParsedHexString yara.HexTokens

var insideOr int

type ByteWithMask struct {
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

%type <tokens> hex_string
%type <tokens> tokens
%type <tokens> token_sequence
%type <token> token_or_range
%type <token> token
%type <bm> byte
%type <alt> alternatives
%type <rng> range

%union {
  integer int64
  token   *yara.HexToken
  tokens  *yara.HexTokens
  bm      ByteWithMask
  alt     *yara.Alternative
  rng     *yara.Jump
}

%%

hex_string
    : _LBRACE_ tokens _RBRACE_
      {
        ParsedHexString = *$2
      }
    ;


tokens
    : token
      {
        $$ = &yara.HexTokens{ Token: []*yara.HexToken{$1} } 
      }
    | token token
      {
        $$ = &yara.HexTokens{ Token: mergeTokens($1, $2) }
      }
    | token token_sequence token
      {
        tokens := append([]*yara.HexToken{$1}, $2.Token...)
        tokens = append(tokens, $3)
        tokens = mergeTokens(tokens...)
        $$ = &yara.HexTokens{ Token: tokens }
      }
    ;


token_sequence
    : token_or_range
      {
        $$ = &yara.HexTokens{ Token: []*yara.HexToken{$1} }
      }
    | token_sequence token_or_range
      {
        appendToken($1, $2)
        $$ = $1
      }
    ;


token_or_range
    : token
      {
        $$ = $1
      }
    |  range
      {
        $$ = &yara.HexToken{ Value: &yara.HexToken_Jump{$1} }
      }
    ;


token
    : byte
      {
        $$ = &yara.HexToken{
          Value: &yara.HexToken_Sequence{
            &yara.BytesSequence{
              Mask: []byte{$1.Mask},
              Value: []byte{$1.Value},
            },
          },
        }
      }
    | _LPARENS_
      {
        insideOr += 1
      }
       alternatives
      {
        $$ = &yara.HexToken{ Value: &yara.HexToken_Alternative{ $3 } }
      }
      _RPARENS_
      {
        insideOr -= 1
        $$ = $<token>4
      }
    ;


range
    : _LBRACKET_ _NUMBER_ _RBRACKET_
      {
        if $2 <= 0 {
          err := yara.Error{
            yara.InvalidJumpLengthError,
            fmt.Sprintf("%d", $2),
          }
          panic(err)
        }

        if insideOr > 0 && $2 > StringChainingThreshold {
          err := yara.Error{
            yara.JumpTooLargeInsideAlternation,
            fmt.Sprintf("%d", $2),
          }
          panic(err)
        }

        $$ = &yara.Jump{ Start: proto.Int64($2), End: proto.Int64($2) }
      }
    | _LBRACKET_ _NUMBER_ _HYPHEN_ _NUMBER_ _RBRACKET_
      {
        if insideOr > 0 &&
          ($2 > StringChainingThreshold || $4 > StringChainingThreshold) {
          err := yara.Error{
            yara.JumpTooLargeInsideAlternation,
            fmt.Sprintf("%d-%d", $2, $4),
          }
          panic(err)
        }

        if $2 < 0 || $4 < 0 {
          err := yara.Error{
            yara.NegativeJump,
            fmt.Sprintf("%d-$d", $2, $4),
          }
          panic(err)
        }

        if $2 > $4 {
          err := yara.Error{
            yara.InvalidJumpRange,
            fmt.Sprintf("%d-%d", $2, $4),
          }
          panic(err)
        }

        $$ = &yara.Jump{ Start: proto.Int64($2), End: proto.Int64($4) }
      }
    | _LBRACKET_ _NUMBER_ _HYPHEN_ _RBRACKET_
      {
        if insideOr > 0 {
          err := yara.Error{
            yara.UnboundedJumpInsideAlternation,
            fmt.Sprintf("%d-", $2),
          }
          panic(err)
        }

        if $2 < 0 {
          err := yara.Error{
            yara.NegativeJump,
            fmt.Sprintf("%d-", $2),
          }
          panic(err)
        }

        $$ = &yara.Jump{ Start: proto.Int64($2) }
      }
    | _LBRACKET_ _HYPHEN_ _RBRACKET_ 
      {
        if insideOr > 0 {
          err := yara.Error{
            yara.UnboundedJumpInsideAlternation,
            "-",
          }
          panic(err)
        }

        $$ = &yara.Jump{}
      }
    ;


alternatives
    : tokens
      {
          $$ = &yara.Alternative{ Tokens: []*yara.HexTokens{$1} }
      }
    | alternatives _PIPE_ tokens
      {
          $1.Tokens = append($1.Tokens, $3)
          $$ = $1
      }
    ;

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

func appendToken(tokens *yara.HexTokens, t *yara.HexToken) {
  if len(tokens.Token) == 0 {
    tokens.Token = []*yara.HexToken{t}
    return
  }

  numTokens := len(tokens.Token)
  lastToken := tokens.Token[numTokens - 1]
  tokens.Token = append(tokens.Token[:numTokens - 1], mergeTokens(lastToken, t)...)
}

func mergeTokens(tokens... *yara.HexToken) (out []*yara.HexToken) {
  if len(tokens) == 0 {
    return
  }

  for _, token := range tokens {
    if len(out) == 0 {
      out = append(out, token)
    } else {
      prev := out[len(out) - 1]
      tokensCanBeMerged := prev.GetSequence() != nil && token.GetSequence() != nil
      if tokensCanBeMerged {
        prev.GetSequence().Value = append(prev.GetSequence().Value, token.GetSequence().Value...)
        prev.GetSequence().Mask = append(prev.GetSequence().Mask, token.GetSequence().Mask...)
      } else {
        out = append(out, token)
      }
    }
  }

  return
}

