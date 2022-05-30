#!/usr/bin/env python3
"Print RTF file as a tree"
from __future__ import print_function
import re, argparse

class RtfBlock:
    def __init__(self, level, text):
        self.level = level
        self.text = text

class RtfFile:
    def __init__(self, path):
        self.path = path
        self.blocks = []

    def decodeChar(self, m):
        return bytes([int(m.group(1), 16)]).decode("windows-1251")

    def load(self):
        level = 0
        text = " ".join(open(self.path).read().split("\n"))
        for m in re.finditer("([{}])([^{}]*)", text):
            b, t = m.group(1, 2)
            if b == "{":
                level += 1
            else:
                level -= 1
            if t != "":
                t = re.sub("\\\\'([0-9a-fA-F]{2})", self.decodeChar, t)
                self.blocks.append(RtfBlock(level, t))
        return self

    def print(self):
        for b in self.blocks:
            head = " " * (b.level - 1) if b.level < 10 else\
                "%d       " % b.level
            print(head + b.text)
                
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("INPUT")
args = parser.parse_args()
RtfFile(args.INPUT).load().print()
