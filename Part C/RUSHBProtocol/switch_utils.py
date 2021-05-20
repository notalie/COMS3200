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

RECVSIZE = 2048

# /x : num hosts
CIDR_CONVERSION = {
	'32':1,
	'31':0,
	'30':2,
	'29':6,
	'28':14,
	'27':30,
	'26':62,
	'25':126,
	'24':252,
	'23':510,
	'22':1022,
	'21':2046,
	'20':4094,
	'19':8190,
	'18':16382,
	'17':32766,
	'16':65534,
	'15':131070,
	'14':262142,
	'13':524286,
	'12':1048574,
	'11':2097150,
	'10':4194302,
	'9':388606,
	'8':16777214,
	'7':33554430,
	'6':67108862,
	'5':134217726,
	'4':268435454,
	'3':536870910,
	'2':1073741822,
	'1':2147483646,
	'0':4294967294
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

	chosen_switches = []
	closest_switch = None

	for switch in current_switch.connected_switches:
		if dst_ip in switch.distance_map:
			chosen_switches.append(switch)

	for adapter in current_switch.connected_adapters:
		if dst_ip == adapter.ip:
			closest_switch = adapter
			break

	if closest_switch == None:
		for switch in chosen_switches:
			if closest_switch == None:
				closest_switch = switch
			elif closest_switch.distance_map[dst_ip] > switch.distance_map[dst_ip]:
				closest_switch = switch

	# Wasn't able to find the connecting switch, use prefix
	if closest_switch == None:
		closest_switch = switch_connection.get_closest_ip(current_switch, dst_ip)

	# Add switches src_ip[src_ip] = really high number to show that it's connected but no idea how large, it will change
	for switch in current_switch.connected_switches:
		if current_switch.last_received_ip != None and switch.src_ip == current_switch.last_received_ip and src_ip not in switch.distance_map:
			switch.distance_map[src_ip] = 1001 # MAX DISTANCE - shouldn't be possible etc
			break

	if len(data[0][12:]) > 1488: # Frag
		MAX_LEN = 1488
		counter = 1488
		flag = MORE_FRAG
		payload = data[0][12:]

		for i in range(0, len(payload), 1488):
			data = payload[i:counter] # Get a range of 1488 (max payload size)
			closest_switch.lastest_packet.append(utils.create_adapter_packet(src_ip, dst_ip, flag, None, data.decode('utf-8')))
			# Create a bunch of payloads here to add, change to use packet to use a for loop I think
			if counter + 1488 >= len(payload):
				flag = END_FRAG
			else:
				flag = MORE_FRAG
			counter += 1488
	else:
		closest_switch.lastest_packet = [utils.create_adapter_packet(src_ip, dst_ip, data[0][11], None, data[0][12:].decode('utf-8'))]
	
	if closest_switch.verified == False: # Hasn't been a handshake in the past few seconds, send the QUERY packet and save the packet to send
		packet = utils.create_switch_packet(closest_switch.my_ip, closest_switch.src_ip, QUERY, 0, 0)
		closest_switch.sock.sendto(packet, (LOCALHOST, closest_switch.port))
	else: # has been verified lately
		closest_switch.sock.sendto(closest_switch.lastest_packet, (LOCALHOST, closest_switch.port))
		closest_switch.lastest_packet = []

	current_switch.last_received_ip = None

def parse_data(data, current_switch):
	if data[0][11] == DISCOVERY:
		# Check if adding the adapters are at the CIDR limit, +1 for the host
		if len(current_switch.connected_adapters) + 1 == CIDR_CONVERSION[current_switch.max_local_ips]:
			pass
		else:
			# Check if the there is too many adapters connected
			switch_greeting.greeting_protocol_receive(data, current_switch)
	elif data[0][11] == DATA or data[0][11] == MORE_FRAG or data[0][11] == END_FRAG:
		parse_data_packet(data, current_switch)

# ----------- Data between a switch and a switch (TCP open to begin with) ------
def parse_switch_data(data, current_switch, port, conn):
	if len(data[0]) == 0:
		return
	if data[0][11] == DISCOVERY:
		max_total = 0
		# Check if adding the switch are at the CIDR limit, +1 for the host
		if len(current_switch.connected_adapters) + 1 == CIDR_CONVERSION[current_switch.max_global_ips]:
			pass
		else: # You can connect switch
			target_ip = switch_greeting.greeting_protocol_receive_switch(data, current_switch, port, conn)

			latest_switch = current_switch.connected_switches[-1]

			# Receive Location from the switch we just connected to 
			data = conn.recvfrom(RECVSIZE)

			current_switch.update_distance(switch_connection.calculate_distance(data[0], current_switch))
			latest_switch.update_distance(switch_connection.calculate_distance(data[0], current_switch))

			if current_switch.is_local == True and current_switch.is_global == True:
				for switch in current_switch.connected_switches:
					packet = utils.create_switch_packet(switch.my_ip, switch.src_ip, DISTANCE, current_switch.local_ip, int(current_switch.distance))
					switch.sock.sendto(packet, (LOCALHOST, switch.port))

			# Send updated data to all connected switches
			for switch in current_switch.connected_switches:
				if switch.src_ip != latest_switch.src_ip:
					packet = utils.create_switch_packet(switch.my_ip, switch.src_ip, DISTANCE, target_ip, latest_switch.distance)
					switch.sock.sendto(packet, (LOCALHOST, switch.port))
	elif data[0][11] == DATA or data[0][11] == MORE_FRAG or data[0][11] == END_FRAG:
		parse_data_packet(data, current_switch)
	elif data[0][11] == LOCATION or DISTANCE:
		switch_connection.parse_data(data[0], current_switch)
	
	elif data[0][11] == QUERY:
		chosen_switch = None
		src_ip = socket.inet_ntoa(data[0][0:4])
		dst_ip = socket.inet_ntoa(data[0][4:8])

		for switch in current_switch.connected_switches:
			if switch.src_ip == src_ip:
				chosen_switch = switch
				break

		# Send an available to the query
		# Create Available packet (dst_ip, src_ip, AVAILABLE, EMPTY_IP, None)
		packet = utils.create_adapter_packet(EMPTY_IP, EMPTY_IP, AVAILABLE, EMPTY_IP, None)
		chosen_switch.sock.sendto(packet, (LOCALHOST, chosen_switch.port)) 

		# set the switch that sent it to be verified == True
		chosen_switch.verified = True
		if chosen_switch.verified_function != None:
			chosen_switch.verified_function.cancel()

		chosen_switch.verified_function = threading.Timer(5, toggle_verified, [chosen_switch])
		chosen_switch.verified_function.start()

		current_switch.last_received_ip = chosen_switch.src_ip

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

		self.last_received_ip = None

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
			self.global_sock.listen()
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
		self.lastest_packet = []

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











		    