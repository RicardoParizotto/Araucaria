#!/usr/bin/env python3
import random
import socket
import sys
import threading
import os

from scapy.all import (
    FieldLenField,
    FieldListField,
    IntField,
    IPOption,
    ShortField,
    get_if_list,
    sniff
)

from scapy.all import IP, TCP, Ether, get_if_hwaddr, get_if_list, sendp

from resist_header import *

PKT_FROM_SHIM_LAYER = 50
PKT_FROM_MASTER_TO_REPLICA =  1
PKT_PING = 2
PKT_PONG = 3
REQUEST_DATA = 4
REPORT_DATA = 5
REPLAY_DATA = 6
PKT_FROM_SWITCH_TO_APP = 7
PKT_REPLAY_FROM_SHIM = 8
PKT_UNORDERED_REPLAY = 9
LAST_PACKET_RECEIVED = 13
PKT_REPLAY_ACK = 20

coordinatorAdress = "10.0.3.3"

UNLOCKED = 0
LOCKED = 1

class shim_layer:
    def __init__(self, pid):
         self.pid = pid
         self.input_log = []
         self.output_log = []
         self.clock = 0
         self.iface = "eth0"
         self.iface_replica = ""
         self.get_if()
         self.lockApplicationProcess = UNLOCKED
         self.app_buffer = []

         #this variables are useful for replay. They should be protected by some lock mechanism
         self.shim_layer_state = "Alive"
         self.global_virtual_round = 0    #this variable will keep the round that starts the replay
         self.determinants_buffer = {}

         self.replay_semaphor = threading.Semaphore(1)     #only one object in the critical section
         self.application_send_messages_semaphor = threading.Semaphore(1)   #this semaphore is to allow only one thing to happen: either send normal messages, or replay

         self.pkts_per_second = [0]
         self.current_measured_second = 0

         self.file_logs = open("shim_logs/"+str(self.pid)+"_log_times.txt", "w")
         self.file_shim = open("shim_logs/"+str(self.pid)+"log.txt", "w")

         self.replayDeterminants = {}

         self.receiveThread = threading.Thread(target=self.receive, args=(self.iface,))
         self.receiveThread.start()

         self.receiveReplicaThread = threading.Thread(target=self.receive, args=(self.iface_replica,))
         self.receiveReplicaThread.start()

         self.tick_seconds_thread = threading.Thread(target=self.tick_seconds, args=())
         self.tick_seconds_thread.start()

         self.send_replay_packets = threading.Thread(target=self.send_replay_packets, args=())
         self.send_replay_packets.start()

    def tick_seconds(self):
        while(True):
            time.sleep(1)
            self.file_logs.write("PKTs:"+ str(self.pkts_per_second[self.current_measured_second]) +", " + str(time.time()) + "\n")
            self.file_logs.flush()
            self.pkts_per_second.append(0)
            self.current_measured_second = self.current_measured_second + 1

    #just increases the clock from the shim layer
    def clock_tick(self):
        self.clock = self.clock + 1
        return self.clock

    #this is supposed to get a list of interfaces. Second interface is suppoesd to be the one for backup
    def get_if(self):
        self.ifaces=get_if_list()
        self.iface_replica=None # "h1-eth0"
        self.ifaces.remove('lo')
        for i in self.ifaces:
            if "eth0" != i and i != None:
                self.iface_replica=i
                break;
    #sniff every packet, fiter it based on the application Protocol
    #and pass it to the handle_packet method
    def receive(self, iface):
        #TODO: i need to filter outgoing packets. I don`t need those here
        print("sniffing on %s" % iface)
        build_lfilter = lambda r: ResistProtocol in r and r[ResistProtocol].flag in [PKT_REPLAY_ACK, LAST_PACKET_RECEIVED, REPLAY_DATA, REQUEST_DATA, PKT_FROM_SWITCH_TO_APP, PKT_UNORDERED_REPLAY]
        sys.stdout.flush()
        sniff(iface = iface, lfilter=build_lfilter,
              prn = lambda x: self.handle_pkt(x))

    #this will send the packets to the replica
    def send_replay_packets(self):
        while(self.shim_layer_state == "Alive"): #this should be in the critical zone
            time.sleep(2)

        round = self.global_virtual_round
        replay_determinants = self.determinants_buffer

        replay_determinants = sorted(replay_determinants, key=lambda x: x['round'])

        for msg_from_coordinator in replay_determinants:
            print("msg from coordinator" + str(msg_from_coordinator))
            if msg_from_coordinator['round'] > round:
                print(msg_from_coordinator['round'])
                for msg_in_shim in self.output_log:
                    print(msg_in_shim)
                    if msg_from_coordinator['lvt'] == msg_in_shim['lvt']:
                        self.replay_semaphor.acquire()
                        print("replay round" +  str(msg_from_coordinator['round']))

                        pkt =  Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff', type=TYPE_RES)
                        pkt = pkt / ResistProtocol(flag=PKT_REPLAY_FROM_SHIM, pid = self.pid, value= msg_in_shim['lvt'], round=msg_from_coordinator['round'])
                        pkt = pkt / IP(dst="10.0.1.1") / TCP(dport=1234, sport=random.randint(49152,65535))
                        sendp(pkt, iface=self.iface, verbose=False)
                        self.file_shim.write("replay" + "\n")
                        #preciso fazer algo para enviar so dps do ack




    def handle_pkt(self, pkt):
        #data being request by the cooordinator?
        if ResistProtocol in pkt and pkt[ResistProtocol].flag == REPLAY_DATA:
            print("packet replay-- on round %d" % (pkt[ResistProtocol].round))
            print(eval(pkt[Raw].load))
            self.iface = self.iface_replica
            self.file_logs.write("CHANGE INTERFACE, :"+str(time.time()) + "\n")
            # process the information received to replay it
            #-----because switches can send unordered packets back, we need something to receive and
            #send unordered packets again to the switch

            self.shim_layer_state = "Replay"
            self.global_virtual_round = pkt[ResistProtocol].round
            self.determinants_buffer = eval(pkt[Raw].load)

            #self.send_replay_packets(replay_determinants=eval(pkt[Raw].load), round=pkt[ResistProtocol].round) l
            #packet unordered in the switch. Send it back
        if ResistProtocol in pkt and pkt[ResistProtocol].flag == PKT_UNORDERED_REPLAY:
            self.file_shim.write("Unordered"+str(pkt[ResistProtocol].round)+"\n")
            #pkt.show2()
            pkt2 =  Ether(src=get_if_hwaddr(self.iface_replica), dst='ff:ff:ff:ff:ff:ff', type=TYPE_RES)
            pkt2 = pkt2 / ResistProtocol(flag=PKT_REPLAY_FROM_SHIM, pid = self.pid, round=pkt[ResistProtocol].round, value=pkt[ResistProtocol].value) / IP(dst=coordinatorAdress)
            sendp(pkt2, iface=self.iface, verbose=False)
            print("replay_unordered")
        if ResistProtocol in pkt and pkt[ResistProtocol].flag == REQUEST_DATA:
            #this is the case the switch failed, and the coordinator is asking for information to recover
            #lock application
            #self.lockApplicationProcess = LOCKED
            self.application_send_messages_semaphor.acquire()   #does not allow send thread to acquire a semaphore. Only releases after recovery
            pkt =  Ether(src=get_if_hwaddr(self.iface_replica), dst='ff:ff:ff:ff:ff:ff', type=TYPE_RES)
            pkt = pkt / ResistProtocol(flag=REPORT_DATA, pid = self.pid) / IP(dst=coordinatorAdress)
            #send packet to the coordinator
            pkt = pkt / Raw(load=str(self.input_log))
            sendp(pkt, iface=self.iface_replica, verbose=False)
        if ResistProtocol in pkt and pkt[ResistProtocol].flag == PKT_REPLAY_ACK:
            self.replay_semaphor.release()
            print("got the miracle")
        if ResistProtocol in pkt and pkt[ResistProtocol].flag == LAST_PACKET_RECEIVED:
            #self.send_buffer()#resend packets in the app_buffer
            #release lock
            #self.lockApplicationProcess = UNLOCKED
            self.application_send_messages_semaphor.release()
            self.file_logs.write("NORMAL PACKETS AGAIN, :"+str(time.time()) + "\n")
            #self.ACK_REPLAY = True
            self.replay_semaphor.release()

        elif ResistProtocol in pkt and pkt[ResistProtocol].flag == PKT_FROM_SWITCH_TO_APP:
            print("got a normal packet")
            self.input_log.append({"lvt":pkt[ResistProtocol].value, "round": pkt[ResistProtocol].round, "pid": pkt[ResistProtocol].pid})
            #print(self.input_log)
    # old function
    def send_buffer(self):
        self.file_logs.write("BUFFER PACKETS, :"+str(time.time()) + "\n")
        for pkt in self.app_buffer:
            sendp(pkt, iface=self.iface, verbose=False)
            self.app_buffer.remove(pkt)
            self.pkts_per_second[self.current_measured_second] = self.pkts_per_second[self.current_measured_second] + 1

    def app_interface_send(self, addr, input):
        pkt =  Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff', type=TYPE_RES)
        pkt = pkt / ResistProtocol(flag=PKT_FROM_SHIM_LAYER, pid = self.pid, value=self.clock) / IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / input
        self.application_send_messages_semaphor.acquire()
        if self.lockApplicationProcess == LOCKED:
            self.app_buffer.append(pkt)
        else:
            self.output_log.append({"lvt":self.clock, "data": input})    #log packets in the output
            sendp(pkt, iface=self.iface, verbose=False)
            self.pkts_per_second[self.current_measured_second] = self.pkts_per_second[self.current_measured_second] + 1
        self.clock_tick()
        self.application_send_messages_semaphor.release()
    #TODO: send everything using this method
    def send(self, addr, input):
        self.output_log.append({"lvt":self.clock_tick(), "data": input})
        print("sending on interface %s to %s" % (self.iface, str(addr)))
        pkt =  Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff', type=TYPE_RES)
        pkt = pkt / ResistProtocol(flag=PKT_FROM_SHIM_LAYER, pid = self.pid, value=self.clock) / IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / input
        #pkt.show2()
        sendp(pkt, iface=self.iface, verbose=False)
