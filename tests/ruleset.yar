include "./true.yar"

import "pe"
import "math"

rule BASIC_BOOL {
condition:
    true
}

rule BASIC_BOOL2 {
condition:
    false
}

rule HEX_STRING {
strings:
    $h1 = {01 23 45 67 89 ab}
    $h2 = {cd ef 01 23 45 67}
condition:
    any of ($h*)
}

rule REGEX1 {
strings:
    $r1 = /first regex/
condition:
    $r1
}

rule REGEX2 {
strings:
    $r1 = /regex with mod i/i
    $r2 = /regex with mod s/s
condition:
    $r1
    or $r2
}

rule STRING1 {
strings:
    $s1 = "ABCDEFG"
condition:
    $s1
}

rule STRING2 {
strings:
    $s1 = "ABCDEFG"
    $s2 = "HIJKLMN"
condition:
    $s1 or $s2
}

rule TAG : tag1 {
condition:
    true
}

rule TAG_STRING : tag2 {
strings:
    $s1 = "ABCDEFG"
condition:
    $s1
}

rule TAGS : tag1 tag2 tag3 {
condition:
    true
}

global rule GLOBAL {
condition:
    true
}

private rule PRIVATE {
condition:
    true
}

rule META {
meta:
    meta_str = "string metadata"
    meta_int = 42
    meta_neg = -42
    meta_true = true
    meta_false = false
condition:
    true
}

rule XOR {
strings:
    $xor1 = "xor!" xor
    $xor2 = "xor?" nocase xor
    $xor3 = /xor_/ xor
    $no_xor1 = "no xor :(" wide
    $no_xor2 = "no xor >:(" ascii nocase
condition:
    any of them
}