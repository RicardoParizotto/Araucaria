#!/usr/bin/env python3
import os
import sys
import time
import ast

from scapy.all import IP, TCP, Ether, get_if_hwaddr, get_if_list, sendp

from scapy.all import (
    TCP,
    FieldLenField,
    FieldListField,
    IntField,
    IPOption,
    ShortField,
    get_if_list,
    sniff
)
from scapy.layers.inet import _IPOption_HDR

import threading

from resist_header import *

#TODO:
#send signal to nodesswitches to send unordered packet back
#implement send back to replica in the switches
#inject a failure in the main switch
#add more hosts*/


PKT_FROM_SHIM_LAYER = 50
PKT_FROM_MASTER_TO_REPLICA =  1
PKT_PING = 2
PKT_PONG = 3
REQUEST_DATA = 4
REPORT_DATA = 5
REPLAY_DATA = 6
PKT_COLLECT_ROUND = 10
PKT_EXPORT_ROUND = 11
PKT_LAST_REPLAY_ROUND = 12


class coordinator:
    def __init__(self, size):
        self.ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
        for i in self.ifaces:
            if "eth0" in i:
                self.iface=i
                break;

        #self.nodes = {"1": "10.0.1.1", "2": "10.0.2.2", "4": "10.0.4.4", "5": "10.0.5.5"}
        #"6": "10.0.6.6", "7": "10.0.7.7", "8": "10.0.8.8"}
        self.nodes = {} #ID and destination of nodes
        self.file_logs = open("shim_logs/coordinator_log_times.txt", "a")

        self.define_nodes(size)

        self.inputPerNode = {}
        self.collectCounter = 0 #variable for controlling the number of nodes that answered with collection
        self.replayInput = {}
        #self.nu_until_collect = #threading.Lock()

        self.safe_round_number = 0 #variable for controllng the round number in case of restore
        self.max_round = 0  #variable to control the last round number in the replay. This should be equal in all replicas

        #pick an interface. IT should be eth0
        self.ifaces.remove(self.iface) #removes eth0 from the interface
        self.master_alive = True  #it starts with the master alive

        self.receiveThread = threading.Thread(target = self.receive)
        self.receiveThread.start()

        self.heartbeatingThread = threading.Thread(target = self.heartbeating)
        self.heartbeatingThread.start()

    #define the set of nodes available in the system
    def define_nodes(self, size):
        for i in range(1, size+1):
            if i != 3:
                self.nodes[str(i)] = "10.0."+str(i)+"."+str(i)

    def collect_state(self):
        self.safe_round_number = -1

        #send message to all the nodes for requesting logs
        for i in self.nodes:
            pkt =  Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff')
            pkt =  pkt / ResistProtocol(flag=REQUEST_DATA) / IP(dst= self.nodes[i])
            sendp(pkt, iface=self.iface, verbose=False)
        #Note: Using the receive thread to receive from all the hosts
        #send packet to the switch to collect the round number from the replica
        pkt =  Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff')
        pkt =  pkt / ResistProtocol(flag=PKT_COLLECT_ROUND) / IP(dst= "10.0.1.1")
        sendp(pkt, iface=self.iface, verbose=False)



        #---after all the nodes answer and the round is collected follow to the aggregation
        while (self.collectCounter < len(self.nodes) and self.safe_round_number < 0):
            time.sleep(0.1)
            #this is not how it should be done
        self.aggregateAndComputeState()
        #send packet telling the switch what is the last round number
        pkt =  Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff')
        pkt =  pkt / ResistProtocol(flag=PKT_LAST_REPLAY_ROUND, round=self.max_round) / IP(dst= "10.0.1.1")
        sendp(pkt, iface=self.iface, verbose=False)

    def aggregateAndComputeState(self):
        self.max_round = 0
        for node in self.inputPerNode.keys():
            #for messages from every node
            for msg in self.inputPerNode[node]:
                #if the ID is not know by the replayInput data structure
                if msg['pid'] not in self.replayInput.keys():
                    self.replayInput[msg['pid']] = []
                #if the specific LVT is not in the set of messages that pid has to replay, include this message and its round number to the set
                if msg['lvt'] not in self.replayInput[msg['pid']]:
                    self.replayInput[msg['pid']].append(msg)
                    if msg['round'] > self.max_round:
                        self.max_round = msg['round']

        #send info for all the self.nodes regarding the aggregated information
        for node in self.replayInput.keys():
            #print(self.replayInput[node])
            pkt =  Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff')
            pkt =  pkt / ResistProtocol(flag=REPLAY_DATA, round=self.safe_round_number) / IP(dst= self.nodes[str(node)])
            pkt = pkt / Raw(load=str(self.replayInput[node]))
            sendp(pkt, iface=self.iface, verbose=False)
        self.file_logs.write("ENDS_AGGREGATION:"+str(time.time()) + "\n" )
        self.file_logs.flush()

    def receive_host_state(self):
        print("sniffing on %s" % iface)
        sys.stdout.flush()
        sniff(iface = self.iface,
              prn = lambda x: self.handle_pkt(x))

    def handle_pkt(self, pkt):
        if ResistProtocol in pkt and pkt[ResistProtocol].flag == PKT_PONG:
            print("pong")
            self.master_alive = True
            sys.stdout.flush()
        if ResistProtocol in pkt and pkt[ResistProtocol].flag == REPORT_DATA:
            if Raw in pkt:
                self.inputPerNode[pkt[ResistProtocol].pid] = eval(pkt[Raw].load)
                self.collectCounter = self.collectCounter + 1
        if ResistProtocol in pkt and pkt[ResistProtocol].flag == PKT_EXPORT_ROUND:
            self.safe_round_number = int(pkt[ResistProtocol].round)

    def heartbeating(self):
        while True:
            time.sleep(5)
            if(self.master_alive):
                self.master_alive = False
                pkt =  Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff', type=TYPE_RES)
                pkt = pkt / ResistProtocol(flag=PKT_PING) / IP(dst="10.0.1.1")
                #pkt.show2()
                print("ping")
                sendp(pkt, iface=self.iface, verbose=False)
            else:
                self.file_logs.write("Failure detected:"+str(time.time()) + "\n" )
                self.file_logs.flush()
                #TODO:I need to trigger the recovery process on shim layers
                self.change_interface()
                self.master_alive = True

                self.collect_state()
                #necessario para nao entrar nessa condicao logo que o novo leader e escolhido
                #envia pacote de start change
                #pkt =  Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff', type = TYPE_RES)
                #pkt = pkt / ResistProtocol(flag = MASTER_CHANGE)
                #sendp(pkt, iface=self.iface, verbose=False)

    def change_interface(self):
        print(('PRIMARY TIMEOUT!!!' + str(self.ifaces)))
        for i in self.ifaces:
            if i:
                self.iface = i
                self.ifaces.remove(i)
                break
        #just starting a new receive thread on the other interface
        self.receiveThread = threading.Thread(target = self.receive)
        self.receiveThread.start()


    def receive(self):
        print("sniffing on %s" % self.iface)
        sys.stdout.flush()
        sniff(iface = self.iface,
              prn = lambda x: self.handle_pkt(x))

    def get_if(self):
        ifs=get_if_list()
        iface=None
        for i in get_if_list():
            if "eth0" in i:
                iface=i
                break;
        if not iface:
            print("Cannot find eth0 interface")
            exit(1)
        return iface


if __name__ == '__main__':
    size = int(sys.argv[1])
    coordinator(size)
