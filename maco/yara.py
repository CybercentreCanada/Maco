import re
from collections import namedtuple
from itertools import cycle
from typing import Dict

import yara_x

RULE_ID_RE = re.compile("(\w+)? ?rule (\w+)")


class SyntaxError(Exception): ...


# Create interfaces that resembles yara-python (but is running yara-x under the hood)
class StringMatchInstance:
    def __init__(self, match: yara_x.Match, file_content: bytes):
        self.matched_data = file_content[match.offset : match.offset + match.length]
        self.matched_length = match.length
        self.offset = match.offset
        self.xor_key = match.xor_key

    def plaintext(self) -> bytes:
        if not self.xor_key:
            # No need to XOR the matched data
            return self.matched_data
        else:
            return bytes(c ^ k for c, k in zip(self.matched_data, cycle(self.xor_key)))


class StringMatch:
    def __init__(self, pattern: yara_x.Pattern, file_content: bytes):
        self.identifier = pattern.identifier
        self.instances = [StringMatchInstance(match, file_content) for match in pattern.matches]
        self._is_xor = any([match.xor_key for match in pattern.matches])

    def is_xor(self):
        return self._is_xor


class Match:
    def __init__(self, rule: yara_x.Rule, file_content: bytes):
        self.rule = rule.identifier
        self.namespace = rule.namespace
        self.tags = list(rule.tags) or []
        self.meta = dict()
        # Ensure metadata doesn't get overwritten
        for k, v in rule.metadata:
            self.meta.setdefault(k, []).append(v)
        self.strings = [StringMatch(pattern, file_content) for pattern in rule.patterns]


class Rules:
    def __init__(self, source: str = None, sources: Dict[str, str] = None):
        Rule = namedtuple("Rule", "identifier namespace is_global")
        if source:
            sources = {"default": source}

        try:
            self._rules = []
            compiler = yara_x.Compiler(relaxed_re_syntax=True)
            for namespace, source in sources.items():
                compiler.new_namespace(namespace)
                for rule_type, id in RULE_ID_RE.findall(source):
                    is_global = True if rule_type == "global" else False
                    self._rules.append(Rule(namespace=namespace, identifier=id, is_global=is_global))
                compiler.add_source(source)
            self.scanner = yara_x.Scanner(compiler.build())
        except yara_x.CompileError as e:
            raise SyntaxError(e)

    def __iter__(self):
        for rule in self._rules:
            yield rule

    def match(self, filepath: str = None, data: bytes = None):
        if filepath:
            with open(filepath, "rb") as fp:
                data = fp.read()

        return [Match(m, data) for m in self.scanner.scan(data).matching_rules]


def compile(source: str = None, sources: Dict[str, str] = None) -> Rules:
    return Rules(source, sources)
