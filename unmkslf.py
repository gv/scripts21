#!/usr/bin/env python3
"Unpack makeself archives without running untrusted code"
import re, argparse, os, subprocess

class Count:
    def __init__(self):
        self.total = self.compressed = 0

def run(args):
    bytes = Count()
    path = args.INPUT
    outPath = os.path.basename(path) + ".contents"
    bytes.total = os.stat(path).st_size
    f = open(path, "rb")
    text = f.read(4*1024).decode("utf-8")
    m = re.search(r"filesizes=\"(\d+)\"", text)
    if not m:
        raise Exception("filesize not found")
    bytes.compressed = int(m.group(1))
    f.seek(bytes.total - bytes.compressed)
    try:
        os.mkdir(outPath)
    except FileExistsError:
        pass
    p = subprocess.Popen(["tar", "xvzC", outPath], stdin=subprocess.PIPE)
    while True:
        b = f.read(4096)
        if not b:
            break
        p.stdin.write(b)
    p.stdin.close()
    r = p.wait()
    if r != 0:
        raise Exception("tar returned %d" % r)
    m = re.search(r"script=\"(.+)\"", text)
    if not m:
        raise Exception("Script name not found")
    script = m.group(1)
    m = re.search(r"scriptargs=\"(.+)\"", text)
    args = m.group(1)
    if not m:
        raise Exception("Script args not found")
    args = args.replace("$0", path)
    args = args.replace("$(pwd)", os.getcwd())
    print("To install: cd \"%s\" && ./%s %s" % (
        outPath, script, args))

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("INPUT")
run(parser.parse_args())
