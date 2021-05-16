import utils
import socket
import sys

LOCALHOST = "127.0.0.1"
EMPTY_IP = "0.0.0.0"

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

RECVSIZE = 1024

# -------------- GREETING PROTOCOL -------------

def is_offer_valid(data):
	# Criteria
	# src ip should be filled
	# dest ip should be empty
	# mode == OFFER
	# assigned ip should not be empty
	if socket.inet_ntoa(data[0:4]) != EMPTY_IP and socket.inet_ntoa(data[4:8]) == EMPTY_IP and int.from_bytes(data[8:11], "big") == 0 and data[11] == OFFER and socket.inet_ntoa(data[12:16]) != EMPTY_IP:
		return True
	else:
		return False

def is_ack_valid(data):
	# Criteria
	# src ip should be filled
	# dest ip should be filled
	# reserved - all 0s
	# mode == ACKNOWLEDGE
	if socket.inet_ntoa(data[0:4]) != EMPTY_IP and socket.inet_ntoa(data[4:8]) != EMPTY_IP and int.from_bytes(data[8:11], "big") == 0 and data[11] == ACKNOWLEDGE:
		return True
	else:
		return False

# Start greeting protocol
def greeting_protocol(PORT_NUM, sock):
	# Send DISCOVERY
	packet = utils.create_adapter_packet(EMPTY_IP, EMPTY_IP, DISCOVERY, EMPTY_IP, None)
	sock.sendto(packet, (LOCALHOST, PORT_NUM))

	# Receive OFFER - need to read input on close
	while True:
		data = sock.recvfrom(RECVSIZE)[0]
		if is_offer_valid(data) == True: # Invalid Data - ignore
			break

	src_ip = socket.inet_ntoa(data[0:4])
	assigned_ip = socket.inet_ntoa(data[12:16]) # assigned ip

	# Send REQUEST
	packet = utils.create_adapter_packet(EMPTY_IP, src_ip, REQUEST, assigned_ip, None)
	sock.sendto(packet, (LOCALHOST, PORT_NUM))

	# Receive ACKNOWLEDGE
	while True:
		data = sock.recvfrom(RECVSIZE)[0]
		# Return data for assigning/break while loop
		if is_ack_valid(data):
			return data

# -------------- SENDING PROTOCOL -------------

def send_data(PORT_NUM, sock, data, ASSIGNED_IP):
	dest_ip = data[1]
	payload = data[2]
	packet = utils.create_adapter_packet(ASSIGNED_IP, dest_ip, DATA, EMPTY_IP, payload)
	sock.sendto(packet, (LOCALHOST, PORT_NUM))

# ------------- RECEIVING PROTOCOL ------------

def check_query(data, ASSIGNED_IP, SWITCH_IP, PORT_NUM, sock):
	if socket.inet_ntoa(data[0:4]) == SWITCH_IP and socket.inet_ntoa(data[4:8]) == ASSIGNED_IP:
		# Create Available packet
		packet = utils.create_adapter_packet(ASSIGNED_IP, SWITCH_IP, AVAILABLE, EMPTY_IP, None)
		sock.sendto(packet, (LOCALHOST, PORT_NUM))
		while True:
			# Wait for Data Packet
			data = sock.recvfrom(RECVSIZE)[0]
			if check_data(data, ASSIGNED_IP) == True: # Print out received packet
				break
		
# Receive Data
def check_data(data, ASSIGNED_IP):
	if socket.inet_ntoa(data[4:8]) == ASSIGNED_IP:
		print("\b" + "\b" + "Received from {}: {}".format(socket.inet_ntoa(data[0:4]), data[12:].decode("utf-8")))
		print(">", end=" ")
		sys.stdout.flush()
		return True
	else:
		return False

def frag_data(data, ASSIGNED_IP, sock):
	to_return = None
	if data[11] == MORE_FRAG:
		pass
	elif data[11] == END_FRAG:
		pass


def recv_data(data, ASSIGNED_IP, SWITCH_IP, PORT_NUM, sock):
	if data[11] == QUERY:
		if data[11] == QUERY:
			check_query(data, ASSIGNED_IP, SWITCH_IP, PORT_NUM, sock)
	elif data[11] == MORE_FRAG:
		pass







