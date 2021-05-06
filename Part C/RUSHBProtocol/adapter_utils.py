import utils
import socket

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


def greeting_protocol(PORT_NUM, sock):
	# Start greeting protocol
	RECVSIZE = 1024
	# Send DISCOVERY
	packet = utils.create_adapter_packet(EMPTY_IP, EMPTY_IP, DISCOVERY, EMPTY_IP, None)
	sock.sendto(packet, (LOCALHOST, PORT_NUM))

	# Receive OFFER
	data = sock.recvfrom(RECVSIZE)[0]
	if is_offer_valid(data) == False: # Invalid Data - ignore
		return None

	src_ip = socket.inet_ntoa(data[0:4])
	assigned_ip = socket.inet_ntoa(data[12:16]) # assigned ip

	# Send REQUEST
	packet = utils.create_adapter_packet(EMPTY_IP, src_ip, REQUEST, assigned_ip, None)
	sock.sendto(packet, (LOCALHOST, PORT_NUM))

	# Receive ACKNOWLEDGE
	data = sock.recvfrom(RECVSIZE)[0]
	if is_ack_valid(data):
		return data # Return data for assigning
	else:
		return None

# -------------- SENDING PROTOCOL -------------

def send_data(PORT_NUM, sock, data, ASSIGNED_IP):
	dest_ip = data[1]
	payload = data[2]
	packet = utils.create_adapter_packet(ASSIGNED_IP, dest_ip, DATA, EMPTY_IP, payload)
	sock.sendto(packet, (LOCALHOST, PORT_NUM))

# ------------- RECEIVING PROTOCOL ------------

def check_query(data, ASSIGNED_IP, SWITCH_IP, PORT_NUM, sock):
	if socket.inet_ntoa(data[0:4]) == SWITCH_IP and socket.inet_ntoa(data[4:8]) == ASSIGNED_IP:
		packet = utils.create_adapter_packet(ASSIGNED_IP, SWITCH_IP, AVAILABLE, EMPTY_IP, None)
		sock.sendto(packet, (LOCALHOST, PORT_NUM))


def recv_data(data, ASSIGNED_IP, SWITCH_IP, PORT_NUM, sock):
	if data[11] == QUERY:
		if data[11] == QUERY:
			check_query(data, ASSIGNED_IP, SWITCH_IP, PORT_NUM, sock)
	elif data[11] == MORE_FRAG or data[11] == END_FRAG:
		pass
	elif data[11] == DATA:
		pass







