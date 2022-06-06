#!/usr/bin/env python3
"Print every branch in every fork which has its own commits for a GH project"
import re, argparse, urllib.request, json, subprocess, sys, os.path

class Project:
    def __init__(self, api, data):
        self.api = api
        self.data = data

    def getMultipage(self, size, template):
        pn = 0
        while pn * self.api.pageSize < size:
            p = self.api.query((template + "?page=%d&per_page=%d") % (
                self.data["full_name"], (pn + 1), self.api.pageSize))
            for b in p:
                yield b
            if len(p) < self.api.pageSize:
                break
            pn += 1

    def getBranches(self):
        return self.getMultipage(1000, "repos/%s/branches")

    def getForks(self):
        return self.getMultipage(self.data["forks_count"], "repos/%s/forks")

class Count:
    def __init__(self):
        self.total = self.done = 0

class StatCount:
    def __init__(self):
        self.projects = 0
        self.branches = 0
        self.originBranches = 0

class Api:
    def __init__(self, args):
        self.args = args
        self.useCurl = 1
        self.count = StatCount()
        self.count.requests = Count()
        self.estimation = StatCount()
        self.estimation.projects = 10
        self.estimation.originBranches = 10
        self.estimation.branches = 100
        self.pageSize = 100
        self.token = os.environ.get("GH_TOKEN")
        if not self.token:
            p = os.path.expanduser("~/.ghtoken")
            if os.path.isfile(p):
                self.token = open(p).read().strip()
        if self.token:
            self.username, self.password = self.token.split(":")
        self.reestimate()

    def download(self, url):
        if 0 and self.token:
            url = "%s%sclient_id=%s&client_secret=%s" % (
                url, "&" if "?" in url else "?", self.username, self.password)
        cmd = ["curl", "-L", "--retry", "99999", url]
        if self.token:
            # cmd += ["-H", "Authorization: token " + self.token]
            cmd += ["-u", self.token]
        if self.args.verbose:
            sys.stderr.write("Running %s ...\n" % (" ".join(cmd)))
            cmd += ["-v"]
        else:
            cmd += ["--silent"]
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        text = p.stdout.read().decode()
        r = p.wait()
        if r != 0:
            raise Exception("curl returned %d" % (r))
        return text

    def query(self, path):
        u = "https://api.github.com/%s" % path
        message = "%4d/%4d <- .../%s" % (
            self.count.requests.done, self.count.requests.total, path)
        sys.stderr.write("\33[2K\r" + message[0:self.width-1])
        if self.useCurl:
            res = self.download(u)
        else:
            req = urllib.request.Request(u)
            res = urllib.request.urlopen(req).read()
        obj = json.loads(res)
        self.count.requests.done += 1
        if 'message' in obj or type(obj) == str:
            raise Exception(obj)
        return obj

    def reestimate(self):
        self.count.requests.total =\
            (self.estimation.projects / self.pageSize + 1) +\
            self.estimation.projects *\
            (self.estimation.originBranches / self.pageSize + 2)

    def printBranchesWithCommits(self):
        h, w = os.popen('stty size', 'r').read().split()
        self.width = int(w)
        originName = self.args.INPUT
        origin = Project(self, self.query("repos/%s" % originName))
        self.estimation.projects = origin.data["forks_count"] + 1
        self.reestimate()
        forks = origin.getForks()
        defBranch = origin.data["default_branch"]
        branches0 = origin.getBranches()
        branchesIndex = {}
        commitIndex = {}
        self.estimation.branches = 0
        for bd in branches0:
            branchesIndex[bd["name"]] = bd
            self.estimation.branches += 1
            commitIndex[bd["commit"]["sha"]] = bd
        self.reestimate()
        for f in forks:
            fp = Project(self, f)
            branches = fp.getBranches()
            for bd in branches:
                obd = branchesIndex.get(bd["name"], branchesIndex[defBranch])
                if bd["commit"]["sha"] in commitIndex:
                    # self.count.requests.done += 1
                    self.count.requests.total -= 1
                    continue
                commitIndex[bd["commit"]["sha"]] = bd
                comp = self.query("repos/%s/compare/%s...%s:%s" % (
                    originName, obd["name"], fp.data["owner"]["login"],
                    bd["name"]))
                if not comp["ahead_by"]:
                    continue
                print("\33[2K\r%d commits https://github.com/%s/commits/%s" % (
                    comp["ahead_by"], fp.data["full_name"], bd["name"]))
                for cd in comp["commits"]:
                    print("%s '%s'" % (
                        cd["sha"][0:8], cd["commit"]["message"]))
        print("\n%d forks, %d original branches" % (
            self.estimation.projects, self.estimation.branches))

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("-v", "--verbose", action="store_true")
parser.add_argument("INPUT")
Api(parser.parse_args()).printBranchesWithCommits()

