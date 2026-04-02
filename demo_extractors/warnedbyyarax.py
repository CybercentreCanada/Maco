"""Demo extractor for testing Yara-x rules that produce warnings."""

from __future__ import annotations

from io import BytesIO

from maco import extractor
from maco import yara as yara_m
from maco.model import ExtractorModel


class WarnedByYaraX(extractor.Extractor):
    """Extractor for testing Yara-x rules that produce warnings."""

    family = "warnedbyyarax"
    author = "alien"
    last_modified = "2026-03-23"
    yara_rule = r"""
/*
 * intentionally bad yara rules that generate warnings
 * these warnings can be found in lib/src/compiler/warnings.rs as of v1.14.0
 */
import "math"
import "hash"

rule cannot_count
{
    strings:
        $a = "a string"
        $b = "another string"
    condition:
        7 of them
}

rule so_true
{
    strings:
        $aa = "VirtualAlloc"
    condition:
        $aa or true
}

rule slow { condition: for any i in (0..filesize-1) : ( int32(i) == 0xcafebabe ) }

rule casing { condition: "AD" == hash.sha256(0,filesize) }

rule loopy { condition: for any i in (0..1000) : ( for any j in (0..1000) : ( true ) ) }
import "math"

rule bools { condition: 2 and 3 }

global rule glob { condition: false }

rule more_glob { condition: glob or true }

rule aaa
{
    condition:
        with a = 1: ( false )
}

rule hex_is_hard
{
    strings:
        $a1 = { 61 61 61 61 }
        $a2= { 0F 84 [4] [0-7] 8D }
    condition:
        2 of ($*) at 0
}

rule real_good_rule
{
    strings:
        $a = /foo/i nocase
        $b = { 00 [1-10] 01 }
    condition:
        0 of them
}
"""

    def run(self, stream: BytesIO, matches: list[yara_m.Match]) -> ExtractorModel:
        """Return a dummy result."""
        return ExtractorModel(family=self.family)
