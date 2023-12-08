from scapy.all import *
import sys, os

TYPE_RES = 0x600
TYPE_IPV4 = 0x800

class ResistProtocol(Packet):
    fields_desc = [    IntField("flag", 0),
                       IntField("value", 0),
                       IntField("pid", 0),
                       IntField("round", 0)]

bind_layers(Ether, ResistProtocol, type=TYPE_RES)
bind_layers(ResistProtocol, IP)
