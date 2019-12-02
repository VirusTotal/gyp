// Code generated by goyacc -p xx -o hex/hex_parser.go hex/hex_grammar.y. DO NOT EDIT.

//line hex/hex_grammar.y:31
package hex

import __yyfmt__ "fmt"

//line hex/hex_grammar.y:31
import (
	"github.com/VirusTotal/gyp/ast"
	gyperror "github.com/VirusTotal/gyp/error"
)

const StringChainingThreshold int = 200

type byteWithMask struct {
	Value byte
	Mask  byte
}

//line hex/hex_grammar.y:69
type xxSymType struct {
	yys     int
	integer int
	bm      byteWithMask
	token   ast.HexToken
	tokens  ast.HexTokens
	bytes   *ast.HexBytes
	hexor   *ast.HexOr
}

const _BYTE_ = 57346
const _MASKED_BYTE_ = 57347
const _NUMBER_ = 57348
const _LBRACE_ = 57349
const _RBRACE_ = 57350
const _LBRACKET_ = 57351
const _RBRACKET_ = 57353
const _HYPHEN_ = 57354
const _LPARENS_ = 57355
const _RPARENS_ = 57356
const _PIPE_ = 57357

var xxToknames = [...]string{
	"$end",
	"error",
	"$unk",
	"_BYTE_",
	"_MASKED_BYTE_",
	"_NUMBER_",
	"_LBRACE_",
	"_RBRACE_",
	"_LBRACKET_",
	"$token",
	"_RBRACKET_",
	"_HYPHEN_",
	"_LPARENS_",
	"_RPARENS_",
	"_PIPE_",
}
var xxStatenames = [...]string{}

const xxEofCode = 1
const xxErrCode = 2
const xxInitialStackSize = 16

//line hex/hex_grammar.y:275

//line yacctab:1
var xxExca = [...]int{
	-1, 1,
	1, -1,
	-2, 0,
	-1, 11,
	8, 3,
	14, 3,
	15, 3,
	-2, 7,
	-1, 18,
	8, 4,
	14, 4,
	15, 4,
	-2, 7,
}

const xxPrivate = 57344

const xxLast = 37

var xxAct = [...]int{

	3, 27, 28, 8, 9, 8, 9, 13, 15, 32,
	4, 26, 6, 20, 6, 11, 24, 25, 23, 21,
	19, 29, 10, 18, 2, 7, 30, 8, 9, 31,
	17, 16, 1, 5, 14, 22, 12,
}
var xxPact = [...]int{

	17, -1000, 1, 14, -1, 23, -1000, -1000, -1000, -1000,
	-1000, -1000, -1, -1000, -1000, 7, -1000, 1, -1000, -1000,
	5, 0, -13, -1000, -1000, 15, -1000, -1000, 1, -2,
	-1000, -1000, -1000,
}
var xxPgo = [...]int{

	0, 0, 36, 7, 10, 35, 34, 33, 25, 32,
	30,
}
var xxR1 = [...]int{

	0, 9, 1, 1, 1, 2, 2, 3, 3, 4,
	10, 4, 6, 6, 6, 6, 5, 5, 7, 7,
	8, 8,
}
var xxR2 = [...]int{

	0, 3, 1, 2, 3, 1, 2, 1, 1, 1,
	0, 4, 3, 5, 4, 3, 1, 3, 1, 2,
	1, 1,
}
var xxChk = [...]int{

	-1000, -9, 7, -1, -4, -7, 13, -8, 4, 5,
	8, -4, -2, -3, -6, 9, -8, -10, -4, -3,
	6, 12, -5, -1, 11, 12, 11, 14, 15, 6,
	11, -1, 11,
}
var xxDef = [...]int{

	0, -2, 0, 0, 2, 9, 10, 18, 20, 21,
	1, -2, 0, 5, 8, 0, 19, 0, -2, 6,
	0, 0, 0, 16, 12, 0, 15, 11, 0, 0,
	14, 17, 13,
}
var xxTok1 = [...]int{

	1,
}
var xxTok2 = [...]int{

	2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
	12, 13, 14, 15,
}
var xxTok3 = [...]int{
	0,
}

var xxErrorMessages = [...]struct {
	state int
	token int
	msg   string
}{}

//line yaccpar:1

/*	parser for yacc output	*/

var (
	xxDebug        = 0
	xxErrorVerbose = false
)

type xxLexer interface {
	Lex(lval *xxSymType) int
	Error(s string)
}

type xxParser interface {
	Parse(xxLexer) int
	Lookahead() int
}

type xxParserImpl struct {
	lval  xxSymType
	stack [xxInitialStackSize]xxSymType
	char  int
}

func (p *xxParserImpl) Lookahead() int {
	return p.char
}

func xxNewParser() xxParser {
	return &xxParserImpl{}
}

const xxFlag = -1000

func xxTokname(c int) string {
	if c >= 1 && c-1 < len(xxToknames) {
		if xxToknames[c-1] != "" {
			return xxToknames[c-1]
		}
	}
	return __yyfmt__.Sprintf("tok-%v", c)
}

func xxStatname(s int) string {
	if s >= 0 && s < len(xxStatenames) {
		if xxStatenames[s] != "" {
			return xxStatenames[s]
		}
	}
	return __yyfmt__.Sprintf("state-%v", s)
}

func xxErrorMessage(state, lookAhead int) string {
	const TOKSTART = 4

	if !xxErrorVerbose {
		return "syntax error"
	}

	for _, e := range xxErrorMessages {
		if e.state == state && e.token == lookAhead {
			return "syntax error: " + e.msg
		}
	}

	res := "syntax error: unexpected " + xxTokname(lookAhead)

	// To match Bison, suggest at most four expected tokens.
	expected := make([]int, 0, 4)

	// Look for shiftable tokens.
	base := xxPact[state]
	for tok := TOKSTART; tok-1 < len(xxToknames); tok++ {
		if n := base + tok; n >= 0 && n < xxLast && xxChk[xxAct[n]] == tok {
			if len(expected) == cap(expected) {
				return res
			}
			expected = append(expected, tok)
		}
	}

	if xxDef[state] == -2 {
		i := 0
		for xxExca[i] != -1 || xxExca[i+1] != state {
			i += 2
		}

		// Look for tokens that we accept or reduce.
		for i += 2; xxExca[i] >= 0; i += 2 {
			tok := xxExca[i]
			if tok < TOKSTART || xxExca[i+1] == 0 {
				continue
			}
			if len(expected) == cap(expected) {
				return res
			}
			expected = append(expected, tok)
		}

		// If the default action is to accept or reduce, give up.
		if xxExca[i+1] != 0 {
			return res
		}
	}

	for i, tok := range expected {
		if i == 0 {
			res += ", expecting "
		} else {
			res += " or "
		}
		res += xxTokname(tok)
	}
	return res
}

func xxlex1(lex xxLexer, lval *xxSymType) (char, token int) {
	token = 0
	char = lex.Lex(lval)
	if char <= 0 {
		token = xxTok1[0]
		goto out
	}
	if char < len(xxTok1) {
		token = xxTok1[char]
		goto out
	}
	if char >= xxPrivate {
		if char < xxPrivate+len(xxTok2) {
			token = xxTok2[char-xxPrivate]
			goto out
		}
	}
	for i := 0; i < len(xxTok3); i += 2 {
		token = xxTok3[i+0]
		if token == char {
			token = xxTok3[i+1]
			goto out
		}
	}

out:
	if token == 0 {
		token = xxTok2[1] /* unknown char */
	}
	if xxDebug >= 3 {
		__yyfmt__.Printf("lex %s(%d)\n", xxTokname(token), uint(char))
	}
	return char, token
}

func xxParse(xxlex xxLexer) int {
	return xxNewParser().Parse(xxlex)
}

func (xxrcvr *xxParserImpl) Parse(xxlex xxLexer) int {
	var xxn int
	var xxVAL xxSymType
	var xxDollar []xxSymType
	_ = xxDollar // silence set and not used
	xxS := xxrcvr.stack[:]

	Nerrs := 0   /* number of errors */
	Errflag := 0 /* error recovery flag */
	xxstate := 0
	xxrcvr.char = -1
	xxtoken := -1 // xxrcvr.char translated into internal numbering
	defer func() {
		// Make sure we report no lookahead when not parsing.
		xxstate = -1
		xxrcvr.char = -1
		xxtoken = -1
	}()
	xxp := -1
	goto xxstack

ret0:
	return 0

ret1:
	return 1

xxstack:
	/* put a state and value onto the stack */
	if xxDebug >= 4 {
		__yyfmt__.Printf("char %v in %v\n", xxTokname(xxtoken), xxStatname(xxstate))
	}

	xxp++
	if xxp >= len(xxS) {
		nyys := make([]xxSymType, len(xxS)*2)
		copy(nyys, xxS)
		xxS = nyys
	}
	xxS[xxp] = xxVAL
	xxS[xxp].yys = xxstate

xxnewstate:
	xxn = xxPact[xxstate]
	if xxn <= xxFlag {
		goto xxdefault /* simple state */
	}
	if xxrcvr.char < 0 {
		xxrcvr.char, xxtoken = xxlex1(xxlex, &xxrcvr.lval)
	}
	xxn += xxtoken
	if xxn < 0 || xxn >= xxLast {
		goto xxdefault
	}
	xxn = xxAct[xxn]
	if xxChk[xxn] == xxtoken { /* valid shift */
		xxrcvr.char = -1
		xxtoken = -1
		xxVAL = xxrcvr.lval
		xxstate = xxn
		if Errflag > 0 {
			Errflag--
		}
		goto xxstack
	}

xxdefault:
	/* default state action */
	xxn = xxDef[xxstate]
	if xxn == -2 {
		if xxrcvr.char < 0 {
			xxrcvr.char, xxtoken = xxlex1(xxlex, &xxrcvr.lval)
		}

		/* look through exception table */
		xi := 0
		for {
			if xxExca[xi+0] == -1 && xxExca[xi+1] == xxstate {
				break
			}
			xi += 2
		}
		for xi += 2; ; xi += 2 {
			xxn = xxExca[xi+0]
			if xxn < 0 || xxn == xxtoken {
				break
			}
		}
		xxn = xxExca[xi+1]
		if xxn < 0 {
			goto ret0
		}
	}
	if xxn == 0 {
		/* error ... attempt to resume parsing */
		switch Errflag {
		case 0: /* brand new error */
			xxlex.Error(xxErrorMessage(xxstate, xxtoken))
			Nerrs++
			if xxDebug >= 1 {
				__yyfmt__.Printf("%s", xxStatname(xxstate))
				__yyfmt__.Printf(" saw %s\n", xxTokname(xxtoken))
			}
			fallthrough

		case 1, 2: /* incompletely recovered error ... try again */
			Errflag = 3

			/* find a state where "error" is a legal shift action */
			for xxp >= 0 {
				xxn = xxPact[xxS[xxp].yys] + xxErrCode
				if xxn >= 0 && xxn < xxLast {
					xxstate = xxAct[xxn] /* simulate a shift of "error" */
					if xxChk[xxstate] == xxErrCode {
						goto xxstack
					}
				}

				/* the current p has no shift on "error", pop stack */
				if xxDebug >= 2 {
					__yyfmt__.Printf("error recovery pops state %d\n", xxS[xxp].yys)
				}
				xxp--
			}
			/* there is no state on the stack with an error shift ... abort */
			goto ret1

		case 3: /* no shift yet; clobber input char */
			if xxDebug >= 2 {
				__yyfmt__.Printf("error recovery discards %s\n", xxTokname(xxtoken))
			}
			if xxtoken == xxEofCode {
				goto ret1
			}
			xxrcvr.char = -1
			xxtoken = -1
			goto xxnewstate /* try again in the same state */
		}
	}

	/* reduction by production xxn */
	if xxDebug >= 2 {
		__yyfmt__.Printf("reduce %v in:\n\t%v\n", xxn, xxStatname(xxstate))
	}

	xxnt := xxn
	xxpt := xxp
	_ = xxpt // guard against "declared and not used"

	xxp -= xxR2[xxn]
	// xxp is now the index of $0. Perform the default action. Iff the
	// reduced production is ε, $1 is possibly out of range.
	if xxp+1 >= len(xxS) {
		nyys := make([]xxSymType, len(xxS)*2)
		copy(nyys, xxS)
		xxS = nyys
	}
	xxVAL = xxS[xxp+1]

	/* consult goto table to find next state */
	xxn = xxR1[xxn]
	xxg := xxPgo[xxn]
	xxj := xxg + xxS[xxp].yys + 1

	if xxj >= xxLast {
		xxstate = xxAct[xxg]
	} else {
		xxstate = xxAct[xxj]
		if xxChk[xxstate] != -xxn {
			xxstate = xxAct[xxg]
		}
	}
	// dummy call; replaced with literal code
	switch xxnt {

	case 1:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line hex/hex_grammar.y:82
		{
			asLexer(xxlex).hexTokens = xxDollar[2].tokens
		}
	case 2:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line hex/hex_grammar.y:90
		{
			xxVAL.tokens = []ast.HexToken{xxDollar[1].token}
		}
	case 3:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line hex/hex_grammar.y:94
		{
			xxVAL.tokens = []ast.HexToken{xxDollar[1].token, xxDollar[2].token}
		}
	case 4:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line hex/hex_grammar.y:98
		{
			xxVAL.tokens = append(append([]ast.HexToken{xxDollar[1].token}, xxDollar[2].tokens...), xxDollar[3].token)
		}
	case 5:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line hex/hex_grammar.y:106
		{
			xxVAL.tokens = []ast.HexToken{xxDollar[1].token}
		}
	case 6:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line hex/hex_grammar.y:110
		{
			xxVAL.tokens = append(xxDollar[1].tokens, xxDollar[2].token)
		}
	case 7:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line hex/hex_grammar.y:118
		{
			xxVAL.token = xxDollar[1].token
		}
	case 8:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line hex/hex_grammar.y:122
		{
			xxVAL.token = xxDollar[1].token
		}
	case 9:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line hex/hex_grammar.y:130
		{
			xxVAL.token = xxDollar[1].bytes
		}
	case 10:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line hex/hex_grammar.y:134
		{
			asLexer(xxlex).insideOr += 1
		}
	case 11:
		xxDollar = xxS[xxpt-4 : xxpt+1]
//line hex/hex_grammar.y:138
		{
			asLexer(xxlex).insideOr -= 1
			xxVAL.token = xxDollar[3].hexor
		}
	case 12:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line hex/hex_grammar.y:147
		{
			lexer := asLexer(xxlex)

			if xxDollar[2].integer <= 0 {
				return lexer.SetError(
					gyperror.InvalidJumpLengthError,
					`invalid jump length: %d`, xxDollar[2].integer)
			}

			if lexer.insideOr > 0 && xxDollar[2].integer > StringChainingThreshold {
				return lexer.SetError(
					gyperror.JumpTooLargeInsideAlternationError,
					`jump too large inside alternation: %d`, xxDollar[2].integer)
			}

			xxVAL.token = &ast.HexJump{
				Start: xxDollar[2].integer,
				End:   xxDollar[2].integer,
			}
		}
	case 13:
		xxDollar = xxS[xxpt-5 : xxpt+1]
//line hex/hex_grammar.y:168
		{
			lexer := asLexer(xxlex)

			if lexer.insideOr > 0 &&
				(xxDollar[2].integer > StringChainingThreshold || xxDollar[4].integer > StringChainingThreshold) {
				return lexer.SetError(
					gyperror.JumpTooLargeInsideAlternationError,
					`jump too large inside alternation: %d-%d`, xxDollar[2].integer, xxDollar[4].integer)
			}

			if xxDollar[2].integer < 0 || xxDollar[4].integer < 0 {
				return lexer.SetError(
					gyperror.NegativeJumpError,
					`negative jump: %d-%d`, xxDollar[2].integer, xxDollar[4].integer)
			}

			if xxDollar[2].integer > xxDollar[4].integer {
				return lexer.SetError(
					gyperror.InvalidJumpRangeError,
					`jump too large inside alternation: %d-%d`, xxDollar[2].integer, xxDollar[4].integer)
			}

			xxVAL.token = &ast.HexJump{
				Start: xxDollar[2].integer,
				End:   xxDollar[4].integer,
			}
		}
	case 14:
		xxDollar = xxS[xxpt-4 : xxpt+1]
//line hex/hex_grammar.y:196
		{
			lexer := asLexer(xxlex)

			if lexer.insideOr > 0 {
				return lexer.SetError(
					gyperror.UnboundedJumpInsideAlternationError,
					`unbounded jump inside alternation: %d`, xxDollar[2].integer)
			}

			if xxDollar[2].integer < 0 {
				return lexer.SetError(
					gyperror.NegativeJumpError,
					`negative jump: %d`, xxDollar[2].integer)
			}

			xxVAL.token = &ast.HexJump{
				Start: xxDollar[2].integer,
			}
		}
	case 15:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line hex/hex_grammar.y:216
		{
			lexer := asLexer(xxlex)

			if lexer.insideOr > 0 {
				return lexer.SetError(
					gyperror.UnboundedJumpInsideAlternationError,
					`unbounded jump inside alternation`)
			}

			xxVAL.token = &ast.HexJump{}
		}
	case 16:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line hex/hex_grammar.y:232
		{
			xxVAL.hexor = &ast.HexOr{
				Alternatives: ast.HexTokens{xxDollar[1].tokens},
			}
		}
	case 17:
		xxDollar = xxS[xxpt-3 : xxpt+1]
//line hex/hex_grammar.y:238
		{
			xxDollar[1].hexor.Alternatives = append(xxDollar[1].hexor.Alternatives, xxDollar[3].tokens)
			xxVAL.hexor = xxDollar[1].hexor
		}
	case 18:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line hex/hex_grammar.y:251
		{
			xxVAL.bytes = &ast.HexBytes{
				Bytes: []byte{xxDollar[1].bm.Value},
				Masks: []byte{xxDollar[1].bm.Mask},
			}
		}
	case 19:
		xxDollar = xxS[xxpt-2 : xxpt+1]
//line hex/hex_grammar.y:258
		{
			xxDollar[1].bytes.Bytes = append(xxDollar[1].bytes.Bytes, xxDollar[2].bm.Value)
			xxDollar[1].bytes.Masks = append(xxDollar[1].bytes.Masks, xxDollar[2].bm.Mask)
		}
	case 20:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line hex/hex_grammar.y:266
		{
			xxVAL.bm = xxDollar[1].bm
		}
	case 21:
		xxDollar = xxS[xxpt-1 : xxpt+1]
//line hex/hex_grammar.y:270
		{
			xxVAL.bm = xxDollar[1].bm
		}
	}
	goto xxstack /* stack new state and value */
}
