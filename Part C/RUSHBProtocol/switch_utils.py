import socket
import sys
import utils
import ipaddress
import adapter_utils
import threading
import switch_greeting
import switch_connection

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

# /x : num hosts
CIDR_CONVERSION = {
	'32':1,
	'24': 256,
	'16':65536
}

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

# Thread that happens once a connection between switches is established
def tcp_thread(current_switch, global_sock):
	last_switch = current_switch.connected_switches[-1]
	dest_ip = last_switch.my_ip

	# Receive location packet and update the distance between the new switch
	last_switch.global_sock = global_sock
	data = global_sock.recv(RECVSIZE)
	current_switch.update_distance(switch_connection.calculate_distance(data, current_switch))

	# Send location to all switches execept the recently connnected switch
	for switch in current_switch.connected_switches:
		if switch.src_ip != last_switch.src_ip:
			packet = utils.create_switch_packet(switch.my_ip, switch.src_ip, DISTANCE, last_switch.src_ip, int(current_switch.distance))
			switch.sock.sendto(packet, (LOCALHOST, switch.port))
			switch.update_map(last_switch.src_ip, current_switch.distance)
		else:
			# Update distance of the switch now that I have the x and y of the switch
			switch.update_distance(switch_connection.calculate_distance(data, current_switch))

	while True:
		# Receive distance packet or receive location packet
		data = global_sock.recv(RECVSIZE)
		switch_connection.parse_data(data, current_switch)

def greeting_protocol(current_switch, port):
	global_sock = switch_greeting.greeting_protocol_send(current_switch, port)
	# Listen on TCP thread that just opened I guess
	stdin_thread = threading.Thread(target=tcp_thread, args=[current_switch, global_sock])
	stdin_thread.start()

# ------------ Data between the switch and the adapter -------------
def parse_data_packet(data, current_switch):
	src_ip = socket.inet_ntoa(data[0][0:4])
	dst_ip = socket.inet_ntoa(data[0][4:8])

	# Size < 1488 is the max size
	if len(data[0][12:]) <= 1488: # Packet doesn't need fragmenting
		chosen_switches = []
		closest_switch = None

		for switch in current_switch.connected_switches:
			eprint(switch)
			eprint(switch.distance_map)

			if dst_ip in switch.distance_map:
				chosen_switches.append(switch)

		for switch in chosen_switches:
			if closest_switch == None:
				closest_switch = switch
			elif closest_switch.distance_map[dst_ip] > switch.distance_map[dst_ip]:
				closest_switch = switch

		# Wasn't able to find the connecting switch, use prefix TODO later
		if closest_switch == None:
			return

		# Save packet
		closest_switch.lastest_packet = utils.create_adapter_packet(src_ip, dst_ip, DATA, None, data[0][12:].decode('utf-8'))
		
		if closest_switch.verified == False: # Hasn't been a handshake in the past few seconds, send the QUERY packet and save the packet to send
			packet = utils.create_switch_packet(closest_switch.my_ip, closest_switch.src_ip, QUERY, 0, 0)
			closest_switch.sock.sendto(packet, (LOCALHOST, closest_switch.port))
		else: # has been verified lately
			closest_switch.sock.sendto(closest_switch.lastest_packet, (LOCALHOST, closest_switch.port))
			closest_switch.lastest_packet = None
	else: # Fragmentation
		pass

def parse_data(data, current_switch):
	if data[0][11] == DISCOVERY:
		# Check if adding the adapters are at the CIDR limit, +1 for the host
		if len(current_switch.connected_adapters) + 1 == CIDR_CONVERSION[current_switch.max_local_ips]:
			pass
		else:
			# Check if the there is too many adapters connected
			switch_greeting.greeting_protocol_receive(data, current_switch)
	elif data[0][11] == DATA:
		parse_data_packet(data, current_switch)

# ----------- Data between a switch and a switch (TCP open to begin with) ------
def parse_switch_data(data, current_switch):
	if data[0][11] == DISCOVERY:
		# Check if adding the switch are at the CIDR limit, +1 for the host
		if len(current_switch.connected_adapters) + 1 == CIDR_CONVERSION[current_switch.max_local_ips]:
			pass
		else: # You can connect switch
			switch_greeting.greeting_protocol_receive_switch(data, current_switch)

			# Send updated data to all connected switches
			for switch in current_switch.connected_switches:
				packet = utils.create_switch_packet(switch.my_ip, switch.src_ip, DISTANCE, current_switch.x_pos, current_switch.y_pos)
				switch.sock.sendto(packet, (LOCALHOST, switch.port))
	elif data[0][11] == DATA:
		parse_data_packet(data, current_switch)
	elif data[0][11] == LOCATION or DISTANCE:
		switch_connection.parse_data(data, current_switch)

# ------------- CLASSES -------------
class Switch():
	def __init__(self, is_local, is_global, x_pos=0, y_pos=0):
		self.is_local = is_local
		self.is_global = is_global
		self.x_pos = int(x_pos)
		self.y_pos = int(y_pos)
		self.connected_adapters = []
		self.connected_switches = []
		# Everything that's indirectly connected
		self.distance_map = {}
		self.distance = 0
		self.global_sock = None

	def set_global_info(self, global_info):
		self.global_info = global_info.split("/")
		self.global_ip = self.global_info[0]
		self.max_global_ips = self.global_info[1]
		self.last_sent_global_ip = ipaddress.ip_address(self.global_ip)

	def set_local_info(self, local_info):
		self.local_info = local_info.split("/")
		self.local_ip = self.local_info[0]
		self.max_local_ips = self.local_info[1]
		self.last_sent_local_ip = ipaddress.ip_address(self.local_ip)

	def initialise_ports(self):
		if self.is_local == True: # UDP Ports
			self.local_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			self.local_sock.bind((LOCALHOST, 0))
			self.local_port = self.local_sock.getsockname()[1]
			print(self.local_port, flush=True)

		if self.is_global == True: # TCP Ports
			self.global_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
			self.global_sock.bind((LOCALHOST, 0))   
			self.global_port = self.global_sock.getsockname()[1]
			print(self.global_port, flush=True)

	def get_next_ip(self):
		self.last_sent_local_ip += 1
		return str(self.last_sent_local_ip)

	def get_next_global_ip(self):
		self.last_sent_global_ip += 1
		return str(self.last_sent_global_ip)

	def add_adapter(self, ip_to_add, port):
		# add after handshake
		self.connected_adapters.append(Adapter(ip_to_add, port))

	def add_switch(self, data, port, sock):
		#Sent: (source_ip=130.0.0.1, destination_ip=130.0.0.2, offset=0, mode=4, assigned_ip=130.0.0.2)
		src_ip = socket.inet_ntoa(data[0:4])
		my_ip = socket.inet_ntoa(data[4:8])
		port = port
		self.connected_switches.append(ConnectedSwitch(my_ip, src_ip, port, sock))
	
	def update_distance(self, distance):
		self.distance += distance
		
class ConnectedSwitch():
	# e.g. [A] -> [B]
	# Where A is me, A is my_ip and B is src_ip with port #
	# my_ip -> what I sent it/what it sent me
	# src_ip -> what it was before it connected/what I gave it
	def __init__(self, my_ip, src_ip, port, sock):
		self.my_ip = my_ip
		self.src_ip = src_ip
		self.port =	port
		self.distance = 0
		self.sock = sock
		self.lastest_packet = None

		# Target IP : Distance
		self.distance_map = {}
		self.connected_ips = []

		self.verified = False
		self.verified_function = None

	def update_distance(self, distance):
		self.distance += distance

	def update_map(self, target_ip, distance):
		if target_ip != self.src_ip:
			self.distance_map[target_ip] = distance


class Adapter():
	def __init__(self, ip, port):
		self.ip = ip
		self.port = port











		    