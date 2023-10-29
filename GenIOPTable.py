import json
import sys
import os
from collections import defaultdict


def parse_modname(name):
    s = name.split(" ")
    return s[1].strip()

def parse_version(vers):
    s = vers.split(" ")
    v = int(s[1], 16)

    major = v >> 8
    minor = v & 0xff

    return str(major) + "." + str(minor)

def parse_export(exp):
    s = exp.split(" ")
    return (int(s[1].strip()), s[2].strip())

def parse_ilb(ilb, exports):
    modname = ""
    version = ""

    for line in ilb:
        if line[0] == '#':
            continue

        if line[0] == 'L':
            modname = parse_modname(line)
            print("adding module", modname)
            continue

        if line[0] == 'V':
            version = parse_version(line)
            continue

        if line[0] == 'F':
            continue

        if line[0] == 'E':
            exp = parse_export(line)
            exports[modname][version][exp[0]] = exp[1]
            continue


def main():
    exports = defaultdict(lambda: defaultdict(dict))

    for arg in sys.argv[1:]:
        print("parsing", arg)
        f = open(arg, 'r')
        parse_ilb(f, exports)
        f.close()

    for mod in exports:
        print("writing", mod)
        out = open(mod + ".json", "w")
        json.dump(exports[mod], out, indent = 4)
        out.close()

main()
