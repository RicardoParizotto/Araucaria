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
REQUEST_SPLIT_DATA = 61
REQUEST_SPLIT_CONTROL = 62
REPORT_DATA = 5
REPLAY_DATA = 6
PKT_FROM_SWITCH_TO_APP = 7
PKT_REPLAY_FROM_SHIM = 8
PKT_UNORDERED_REPLAY = 9
LAST_PACKET_RECEIVED = 13
PKT_REPLAY_ACK = 20
PKT_APP_ACK = 22
PKT_REPLAY_STRONG_EVENTUAL = 66

coordinatorAdress = "10.0.3.3"

UNLOCKED = 0
LOCKED = 1

CONSISTENCY_MODELS = ["STRONG", "EVENTUAL", "STRONG_EVENTUAL"]

CONSISTENCY = "STRONG_EVENTUAL"

class shim_layer:
    def __init__(self, pid, size):
         self.pid = pid
         self.input_log = []
         self.output_log = []
         self.clock = 0
         self.iface = "eth0"
         self.iface_replica = ""
         self.get_if()
         self.lockApplicationProcess = UNLOCKED
         self.app_buffer = []

         self.received_determinants_for_replay = ""

         self.local_determinants = []          #determinants splitted into different elements of a list
         self.local_determinants_index = 0     #current element of list being forwarded to the coordinator

         #this variables are useful for replay. They should be protected by some lock mechanism
         #self.shim_layer_state = "Alive"
         self.shim_replay_event = threading.Event()
         self.global_virtual_round = 0    #this variable will keep the round that starts the replay
         self.determinants_buffer = {}

         self.replay_semaphor = threading.Semaphore(1)     #only one object in the critical section
         self.application_send_messages_semaphor = threading.Semaphore(1)   #this semaphore is to allow only one thing to happen: either send normal messages, or replay
         self.sniffer_ready = threading.Event()   #this is for signaling an ack for the application receive

         self.pkts_per_second = [0]
         self.current_measured_second = 0

         self.file_logs = open("shim_logs/"+str(self.pid)+"log_size"+str(size)+".txt", "w")
         #self.file_shim = open("shim_logs/"+str(self.pid)+"log.txt", "w")

         self.replayDeterminants = {}

         self.receiveThread = threading.Thread(target=self.receive, args=(self.iface,))
         self.receiveThread.start()

         self.receiveReplicaThread = threading.Thread(target=self.receive, args=(self.iface_replica,))
         self.receiveReplicaThread.start()

         self.tick_seconds_thread = threading.Thread(target=self.tick_seconds, args=())
         #self.tick_seconds_thread.start()

         self.send_replay_packets = threading.Thread(target=self.send_replay_packets, args=())
         self.send_replay_packets.start()

         #TODO: need to communicate with the controller or keep more state in the switch. Currently doing it without coordinatorAdress
         self.garbageCollectorThread = threading.Thread(target=self.garbage_collector, args=())
         #self.garbageCollectorThread.start()   #turnoff for correct recovery in asynchrnous scenario (orphan messages)

    #probably you want to comment this function if testing with orphan-packets. Often, 5 packets are not enough.
    def garbage_collector(self):
        while(True):
            time.sleep(2)
            if len(self.output_log) > 15:
                # Keep the last 5 elements and discard the rest
                self.application_send_messages_semaphor.acquire()
                self.output_log[:] = sorted(self.output_log, key=lambda x: x['lvt'])[-5:]
                self.input_log[:] = sorted(self.input_log, key=lambda x: x['round'])[-5:]
                self.application_send_messages_semaphor.release()

    #collects packets acknowledge per-second and saves in a file
    def tick_seconds(self):
        while(True):
            time.sleep(1)
            self.file_logs.flush()
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
        build_lfilter = lambda r: ResistProtocol in r and r[ResistProtocol].flag in [REQUEST_SPLIT_DATA, PKT_APP_ACK, PKT_REPLAY_ACK, LAST_PACKET_RECEIVED, REPLAY_DATA, REQUEST_DATA, PKT_FROM_SWITCH_TO_APP, PKT_UNORDERED_REPLAY]
        sys.stdout.flush()
        sniff(iface = iface, lfilter=build_lfilter,
              prn = lambda x: self.handle_pkt(x))

    #this will send the packets to the replica
    def send_replay_packets(self):
        self.shim_replay_event.wait()
        round = self.global_virtual_round
        replay_determinants = self.determinants_buffer

        replay_determinants = sorted(replay_determinants, key=lambda x: x['round'])

        last_replay_packet = max(replay_determinants, key=lambda x: x['round'])

        replay_counter = 0

        #this condition is to release processes in case the replay does not need to replay anything.
        #happens when the replica already has all the packets from this LP
        #we could do that at the coordinator :D
        if (round >= last_replay_packet['round']):
            self.file_logs.write("Recovery: "+str(time.time()) + "\n")
            self.file_logs.flush()
            self.application_send_messages_semaphor.release()
            self.sniffer_ready.set() #just in case the replica received the packet but the ack was not sent to the servers
        else:
            if(CONSISTENCY == "STRONG"):
                for msg_from_coordinator in replay_determinants:
                    print("msg from coordinator" + str(msg_from_coordinator))
                    if msg_from_coordinator['round'] > round:
                        print(msg_from_coordinator['round'])
                        for msg_in_shim in self.output_log:
                            #print(msg_in_shim)
                            if msg_from_coordinator['lvt'] == msg_in_shim['lvt']:
                                self.replay_semaphor.acquire()
                                #print("replay round" +  str(msg_from_coordinator['round']))
                                replay_counter = replay_counter + 1
                                pkt =  Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff', type=TYPE_RES)
                                pkt = pkt / ResistProtocol(flag=PKT_REPLAY_FROM_SHIM, pid = self.pid, value= msg_in_shim['lvt'], round=msg_from_coordinator['round'])
                                pkt = pkt / IP(dst="10.0.1.1") / TCP(dport=1234, sport=random.randint(49152,65535))
                                sendp(pkt, iface=self.iface, verbose=False)
                                self.file_logs.write("REPLAY:" + "\n")
                                #preciso fazer algo para enviar so dps do ack
            elif(CONSISTENCY == "STRONG_EVENTUAL"):
                msg_to_replay = [element for element in self.output_log if element['lvt'] == last_replay_packet['lvt']]
                pkt =  Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff', type=TYPE_RES)
                pkt = pkt / ResistProtocol(flag=PKT_REPLAY_STRONG_EVENTUAL, pid = self.pid, value=  msg_to_replay[0]['lvt'], round=last_replay_packet['round'])
                pkt = pkt / IP(dst="10.0.1.1")
                sendp(pkt, iface=self.iface, verbose=False)
                pkt.show2()
                self.file_logs.write("REPLAY:" + "\n")
        self.file_logs.write("REPLAY_SIZE:" + str(replay_counter) + "\n")

    #this splits our local determinants
    #used before sending to the coordinator to avoid sending large strings that can not fit the link
    def split_determinants(self, determinants_string):
        while len(determinants_string) > 1000:
            self.local_determinants.append(determinants_string[0:999])
            determinants_string = determinants_string[999:]
        if(len(determinants_string) > 0):
            self.local_determinants.append(determinants_string)

    def handle_pkt(self, pkt):
        #data being request by the cooordinator?
        if ResistProtocol in pkt and pkt[ResistProtocol].flag == REPLAY_DATA:
            #print("packet replay-- on round %d" % (pkt[ResistProtocol].round))
            #print(eval(pkt[Raw].load))
            rcv_data = eval(pkt[Raw].load)
            self.received_determinants_for_replay = self.received_determinants_for_replay + rcv_data["fragment"]
            if int(rcv_data["index"] == 0):
                self.iface = self.iface_replica
                self.file_logs.flush()
                self.file_logs.write("CHANGE INTERFACE :"+str(time.time()) + "\n")
                self.file_logs.flush()
            if int(rcv_data["index"]) == int(pkt[ResistProtocol].pid) - 1:  #this is the last fragment
                #this should increase only after all fragments are received
                self.determinants_buffer = eval(self.received_determinants_for_replay) #converts string into determinants
                self.global_virtual_round = pkt[ResistProtocol].round #this is the replica round
                #self.shim_layer_state = "Replay"
                self.shim_replay_event.set()   #trigger the replay in this particular host
            else: #request the remainder data
                pkt_reply =  Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff', type=TYPE_RES)
                pkt_reply =  pkt_reply / ResistProtocol(flag=REQUEST_SPLIT_CONTROL, pid=self.pid) / IP(dst= coordinatorAdress)
                #print(self.nodes[str(pkt[ResistProtocol].pid)])
                sendp(pkt_reply, iface=self.iface, verbose=False)

        if ResistProtocol in pkt and pkt[ResistProtocol].flag == PKT_UNORDERED_REPLAY:
            #self.file_shim.write("Unordered" + str(pkt[ResistProtocol].round) + "\n")
            pkt2 =  Ether(src=get_if_hwaddr(self.iface_replica), dst='ff:ff:ff:ff:ff:ff', type=TYPE_RES)
            pkt2 = pkt2 / ResistProtocol(flag=PKT_REPLAY_FROM_SHIM, pid = self.pid, round=pkt[ResistProtocol].round, value=pkt[ResistProtocol].value) / IP(dst=coordinatorAdress)
            sendp(pkt2, iface=self.iface, verbose=False)

            print("replay_unordered" + str(pkt[ResistProtocol].round))
        if ResistProtocol in pkt and pkt[ResistProtocol].flag == REQUEST_DATA:
            #this is the case the switch failed, and the coordinator is asking for information to recover
            #lock application
            self.application_send_messages_semaphor.acquire()   #does not allow send thread to acquire a semaphore.
            #Only releases after recovery
            pkt2 =  Ether(src=get_if_hwaddr(self.iface_replica), dst='ff:ff:ff:ff:ff:ff', type=TYPE_RES)
            #send packet to the coordinator
            #i need to split t his content. Otherwise it breaks because it is too long
            determinants = str(self.input_log)
            self.split_determinants(determinants)

            pkt2 = pkt2 / ResistProtocol(flag=REPORT_DATA, pid = self.pid, round = len(self.local_determinants)) / IP(dst=coordinatorAdress)
            pkt2 = pkt2 / Raw(load=str({"index": self.local_determinants_index, "fragment": self.local_determinants[self.local_determinants_index]}))
            self.local_determinants_index = self.local_determinants_index + 1
            sendp(pkt2, iface=self.iface_replica, verbose=False)

        if ResistProtocol in pkt and pkt[ResistProtocol].flag == REQUEST_SPLIT_DATA:
            pkt2 =  Ether(src=get_if_hwaddr(self.iface_replica), dst='ff:ff:ff:ff:ff:ff', type=TYPE_RES)
            pkt2 = pkt2 / ResistProtocol(flag=REPORT_DATA, pid = self.pid, round = len(self.local_determinants)) / IP(dst=coordinatorAdress)
            pkt2 = pkt2 / Raw(load=str({"index": self.local_determinants_index, "fragment": self.local_determinants[self.local_determinants_index]}))
            self.local_determinants_index = self.local_determinants_index + 1
            pkt2.show2()
            sendp(pkt2, iface=self.iface_replica, verbose=False)

        if ResistProtocol in pkt and pkt[ResistProtocol].flag == PKT_REPLAY_ACK:
            self.replay_semaphor.release()
            print("got the ack")
        if ResistProtocol in pkt and pkt[ResistProtocol].flag == LAST_PACKET_RECEIVED:
            #self.send_buffer()#resend packets in the app_buffer
            #release lock
            #self.lockApplicationProcess = UNLOCKED
            self.application_send_messages_semaphor.release()
            self.file_logs.flush()
            self.file_logs.write("RESUME :"+str(time.time()) + "\n")
            self.file_logs.flush()
            #self.ACK_REPLAY = True
            self.replay_semaphor.release()
        if ResistProtocol in pkt and pkt[ResistProtocol].flag == PKT_APP_ACK:
            self.sniffer_ready.set()
            print("got ack")

        elif ResistProtocol in pkt and pkt[ResistProtocol].flag == PKT_FROM_SWITCH_TO_APP:
            print("got a normal packet")
            self.input_log.append({"lvt":pkt[ResistProtocol].value, "round": pkt[ResistProtocol].round, "pid": pkt[ResistProtocol].pid})
            #print(self.input_log)

    def app_interface_send(self, addr, src, input):
        pkt =  Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff', type=TYPE_RES)
        pkt = pkt / ResistProtocol(flag=PKT_FROM_SHIM_LAYER, pid = self.pid, value=self.clock) / IP(src=src,dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / input
        self.application_send_messages_semaphor.acquire()
        self.output_log.append({"lvt":self.clock, "data": input})    #log packets in the output
        print("sending on interface %s to %s" % (self.iface, str(addr)))
        sendp(pkt, iface=self.iface, verbose=False)
        self.sniffer_ready.wait()
        self.pkts_per_second[self.current_measured_second] = self.pkts_per_second[self.current_measured_second] + 1
        self.clock_tick()
        self.application_send_messages_semaphor.release()
