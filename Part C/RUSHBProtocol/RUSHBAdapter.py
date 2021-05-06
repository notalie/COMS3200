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
if len(sys.argv) != 2:
	sys.exit() # Bad args

PORT_NUM = int(sys.argv[1])
ASSIGNED_IP = EMPTY_IP
SWITCH_IP = EMPTY_IP

def parse_input(data):
	split_data = data.split()
	if split_data[0] == 'send': # Ignore data if wrong
		adapter_utils.send_data(PORT_NUM, sock, split_data, ASSIGNED_IP)

# Connect to socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

while True:
	data = adapter_utils.greeting_protocol(PORT_NUM, sock)
	# Keep repeating the protocol until the right packet is received I think?
	if data != None:
		ASSIGNED_IP = socket.inet_ntoa(data[12:16])
		SWITCH_IP = socket.inet_ntoa(data[0:4])
		break

# Initial print of >
print(">", end=" ")
sys.stdout.flush()

def recv_packets(sock):
	while True:
		data = sock.recvfrom(RECVSIZE)[0]
		adapter_utils.recv_data(data, ASSIGNED_IP, SWITCH_IP, PORT_NUM, sock)

def read_stdin():
	# Accept stdin
	while True:
		data = sys.stdin.readline()
		if len(data) > 0:
			parse_input(data) 
			print(">", end=" ")
			sys.stdout.flush()
   	

# Need to make two threads, one to read from 
# stdin and another to read from the port 
t1 = threading.Thread(target=recv_packets, args=(sock,))
t2 = threading.Thread(target=read_stdin, args=[])
t1.start()
t2.start()








