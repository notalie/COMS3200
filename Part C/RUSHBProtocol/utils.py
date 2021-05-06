import sys
import traceback
import os.path
import socket
import time

RECV_SIZE = 4096
TIME_OUT = 5

DISCOVERY = 0x01
OFFER = 0x02
REQUEST = 0x03
ACKNOWLEDGE = 0x04
DATA = 0x05
QUERY = 0x06
AVAILABLE = 0x07
LOCATION = 0x08
DISTANCE = 0x09
MORE_FRAG = 0x0a
END_FRAG = 0x0b
INVALID = 0x00

def get_zeroes():
    zero = 0
    return zero.to_bytes(3, "big")

def str_to_int(string):
    b_str = string.encode("UTF-8")
    return int.from_bytes(b_str, byteorder='big')


def int_to_str(integer, size=11):
    return integer.to_bytes(size, byteorder='big').decode("UTF-8")


def ip_to_int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


def int_to_ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))

def create_adapter_packet(src_ip, dest_ip, mode, assigned_ip, data):
    if mode == DISCOVERY or mode == REQUEST: # Part of Greeting Protocol
        packet = socket.inet_aton(src_ip)
        packet += socket.inet_aton(dest_ip)
        packet += get_zeroes()
        packet += mode.to_bytes(1, "big")
        packet += socket.inet_aton(assigned_ip)
        return packet
    elif mode == AVAILABLE: # Query protocol
        packet = socket.inet_aton(src_ip)
        packet += socket.inet_aton(dest_ip)
        packet += get_zeroes()
        packet += mode.to_bytes(1, "big")
        return packet
        pass
    elif mode == DATA: # Commandline interface
        packet = socket.inet_aton(src_ip)
        packet += socket.inet_aton(dest_ip)
        packet += get_zeroes()
        packet += mode.to_bytes(1, "big")
        packet += data.strip('"').encode('utf-8')
        return packet
