#!/usr/bin/env python3
import pexpect
import argparse
import subprocess
import os
import sys

MAKEFILE_PATH = "/home/p4/tutorials/exercises/Resist-Bmv2/Makefile"

class MininetProc:
    def __init__(self, size) -> None:
        self.proc = pexpect.spawn("make run", cwd=os.path.dirname(MAKEFILE_PATH), encoding="utf-8")
        self.proc.logfile_read = sys.stdout
        self.size = size

    def run_coordinator(self):
        self.proc.expect("mininet> ", timeout=None)
        self.proc.sendline(f"h3 python3 coordinator.py "+str(self.size)+" &")

    def run_server(self, id):
        self.proc.expect("mininet> ", timeout=None)
        self.proc.sendline(f"h"+str(id)+" python3 application2.py "+str(id)+" "+str(self.size)+" &")

    def wait(self):
        self.proc.expect("mininet> ", timeout=None)
        x = input()


def main(size):
    mininet_proc = MininetProc(size)
    mininet_proc.run_coordinator()

    for i in range(1,size + 1):
        if(i != 3):  #3 is the coordinator
            mininet_proc.run_server(id=i)

    mininet_proc.wait()

if __name__ == "__main__":
    size = int(sys.argv[1])
    main(size)
