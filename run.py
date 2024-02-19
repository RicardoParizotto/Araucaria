#!/usr/bin/env python3
import pexpect
import argparse
import subprocess
import os
import sys
import time
import threading

MAKEFILE_PATH = "/home/p4/tutorials/exercises/Araucaria/Makefile"

CLI_PATH = "/home/p4/tutorials/exercises/Araucaria"

class CliProc:
    def __init__(self) -> None:
        self.proc = pexpect.spawn("bm_CLI", cwd=os.path.dirname(CLI_PATH), encoding="utf-8")
        self.proc.logfile_read = sys.stdout

    def  simulate_failure(self):
        self.proc.expect("RuntimeCmd: ", timeout=None)
        self.proc.sendline(f"register_write simulateFailure 0 1")

    def  simulate_orphans(self):
        self.proc.expect("RuntimeCmd: ", timeout=None)
        self.proc.sendline(f"register_write simulate_orphans 0 1")
        self.proc.expect("RuntimeCmd: ", timeout=None)
        time.sleep(4)
        self.proc.sendline(f"register_write simulateFailure 0 1")
        self.proc.expect("RuntimeCmd> ", timeout=None)


    def wait(self):
        self.proc.expect("RuntimeCmd> ", timeout=None)
        #x = input()



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
        #ID: the process unique # IDEA:
        #size: the total amount of processes
        self.proc.sendline(f"h"+str(id)+" python3 application2.py "+  str(id) +" "+str(self.size)+" &")

    def wait(self):
        self.proc.expect("mininet> ", timeout=None)

        x = input()

def run_experiment(size):
    file = open("includes/sizedef.p4", "w+")
    file.write("#define CLUSTER_SIZE " + str(size - 1))   #tem que ser -1 pq sim
    file.close()
    mininet_proc = MininetProc(size)
    mininet_proc.run_coordinator()

    for i in range(1,size + 1):
        if(i != 3):  #3 is the coordinator
            mininet_proc.run_server(id=i)

    mininet_proc.wait()

def simulate_switch_orphan():
    cliProcess = CliProc()
    cliProcess.simulate_orphans()
    #cliProcess.wait()

def simulate_switch_failure():
    cliProcess = CliProc()
    cliProcess.simulate_failure()
    cliProcess.wait()

if __name__ == "__main__":
    size = int(sys.argv[1])

    mode = sys.argv[2]

    if mode == "bmv2":
        run_experiment(size)
    elif mode == "cli":
        simulate_switch_orphan()
        #time.sleep(4)
        #simulate_switch_failure()
    else:
        print("error")
