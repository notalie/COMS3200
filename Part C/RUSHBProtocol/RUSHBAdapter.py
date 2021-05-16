import utils
import sys
import socket
import ipaddress
import adapter_utils
import threading

LOCALHOST = "127.0.0.1"
EMPTY_IP = "0.0.0.0"
RECVSIZE = 1024

# python3 RUSHBAdapter.py port#
PORT_NUM = int(sys.argv[1])
ASSIGNED_IP = EMPTY_IP
SWITCH_IP = EMPTY_IP

def parse_input(data):
	split_data = data.split()
	if split_data[0] == 'send': # Ignore data if wrong
		adapter_utils.send_data(PORT_NUM, sock, split_data, ASSIGNED_IP)

# Connect to socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Greeting Protocol
data = adapter_utils.greeting_protocol(PORT_NUM, sock)
ASSIGNED_IP = socket.inet_ntoa(data[12:16])
SWITCH_IP = socket.inet_ntoa(data[0:4])

# Initial print of >


def recv_packets(sock):
	sys.stdout.flush()
	while True:
		data = sock.recvfrom(RECVSIZE)[0]	
		adapter_utils.recv_data(data, ASSIGNED_IP, SWITCH_IP, PORT_NUM, sock)

def read_stdin():
	# Accept stdin
	try:
		while True:
			data = input("> ")
			if len(data) > 0:
				parse_input(data) 
				sys.stdout.flush()
	except EOFError: 
		sys.exit() # Stop receiving stdin in an EOF
   	

# Need to make two threads, one to read from 
# stdin and another to read from the port 
t1 = threading.Thread(target=recv_packets, args=(sock,))
t2 = threading.Thread(target=read_stdin, args=[])
t1.start()
t2.start()








