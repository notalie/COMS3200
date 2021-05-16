import socket
import adapter_utils
import utils

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

def is_discovery_valid(data, current_switch):
	# Check discovery make sure everything but the mode is 0
	if int.from_bytes(data[0][0:11], "big") == 0 and int.from_bytes(data[0][12:], "big") == 0:
		return True
	else:
		return False

def is_request_valid(data, current_switch, ASSIGNED_IP):
	if socket.inet_ntoa(data[12:16]) != ASSIGNED_IP:
		return False
	elif socket.inet_ntoa(data[0:4]) != EMPTY_IP:
		return False
	elif current_switch.is_local == True and current_switch.is_global == False and socket.inet_ntoa(data[4:8]) != current_switch.local_ip:
		return False
	elif current_switch.is_global == True and current_switch.is_local == False and socket.inet_ntoa(data[4:8]) != current_switch.global_ip:
		return False
	elif int.from_bytes(data[8:11], "big") != 0:
		return False
	else:
		return True

# ------------------- WHEN STDIN SAYS TO CONNECT 
def greeting_protocol_send(current_switch, port):
	port = int(port)
	# Assign global sock to listen on
	global_sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
	global_sock.connect((LOCALHOST, port))

	data = adapter_utils.greeting_protocol(port, global_sock)
	# Store src ip and dest ip
	current_switch.add_switch(data, port, global_sock)

	# Send location packet
	switch = current_switch.connected_switches[-1]
	packet = utils.create_switch_packet(switch.my_ip, switch.src_ip, LOCATION, current_switch.x_pos, current_switch.y_pos)
	global_sock.sendto(packet, (LOCALHOST, switch.port))
	return global_sock

# ------------------ DISCOVERY FROM ADAPTER
def greeting_protocol_receive(data, current_switch):
	while True:
		if is_discovery_valid(data, current_switch) == False:
			data = current_switch.local_sock.recvfrom(RECVSIZE)
		else:
			break
	
	port = data[1][1]

	# Send OFFER packet (src_ip, dest_ip, mode, assigned_ip, data):
	ASSIGNED_IP = current_switch.get_next_ip()
	packet = utils.create_adapter_packet(current_switch.local_ip, EMPTY_IP, OFFER, ASSIGNED_IP, None)
	current_switch.local_sock.sendto(packet, (LOCALHOST, port))

	# Receive REQUEST
	data = current_switch.local_sock.recvfrom(RECVSIZE)
	while True:
		if is_request_valid(data[0], current_switch, ASSIGNED_IP) == False:
			data = current_switch.local_sock.recvfrom(RECVSIZE)
		else:
			break

	packet = utils.create_adapter_packet(current_switch.local_ip, ASSIGNED_IP, ACKNOWLEDGE, ASSIGNED_IP, None)
	current_switch.local_sock.sendto(packet, (LOCALHOST, port))

	current_switch.add_adapter(ASSIGNED_IP, port)

# ------------------ DISCOVERY FROM SWITCH

def greeting_protocol_receive_switch(data, current_switch, port, conn):
	while True:
		if is_discovery_valid(data, current_switch) == False:
			data = conn.recvfrom(RECVSIZE)
		else:
			break

	# Send OFFER packet (src_ip, dest_ip, mode, assigned_ip, data):
	ASSIGNED_IP = current_switch.get_next_global_ip()
	packet = utils.create_adapter_packet(current_switch.global_ip, EMPTY_IP, OFFER, ASSIGNED_IP, None)
	conn.sendto(packet, (LOCALHOST, port))

	# Receive REQUEST
	data = conn.recvfrom(RECVSIZE)
	while True:
		if is_request_valid(data[0], current_switch, ASSIGNED_IP) == False:
			data = conn.recvfrom(RECVSIZE)
		else:
			break

	# Send ACK packet
	packet = utils.create_adapter_packet(current_switch.global_ip, ASSIGNED_IP, ACKNOWLEDGE, ASSIGNED_IP, None)
	conn.sendto(packet, (LOCALHOST, port))

	packet = utils.create_adapter_packet(ASSIGNED_IP, current_switch.global_ip, ACKNOWLEDGE, ASSIGNED_IP, None)
	current_switch.add_switch(packet, port, conn)

	added_switch = current_switch.connected_switches[-1]

	# Send Location packet after a successful connection
	packet = utils.create_switch_packet(added_switch.my_ip, added_switch.src_ip, LOCATION, int(current_switch.x_pos), int(current_switch.y_pos))
	conn.sendto(packet, (LOCALHOST, port))

	return ASSIGNED_IP














