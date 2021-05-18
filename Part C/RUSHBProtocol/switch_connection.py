import math
import ipaddress
import sys
import socket
import utils
import threading
import switch_utils

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

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def calculate_distance(data, current_switch):
	other_x = int.from_bytes(data[12:14], "big")
	other_y = int.from_bytes(data[14:16], "big")
	distance = math.sqrt(math.pow(other_x - int(current_switch.x_pos), 2) + math.pow(other_y - int(current_switch.y_pos), 2))
	return distance

def toggle_verified(chosen_switch):
	chosen_switch.verified = False
	threading.Timer(5, toggle_verified, [chosen_switch]).start()

def convert_ips_to_binary(ip):
    split_list = ip.split(".")
    binary = ("").join([format(int(i), '08b') for i in split_list])
    return binary

def match_ips(target, l):
	small = None
	large = None
	i = 0
	largest_num = None
	for j, s in enumerate(l):
		if s == None:
			continue
		if len(target) > len(s): 
			small = s
			large = target
		else:
			small = target
			large = s
         
		index = 0;    
		for c in s:
			if index == len(small):
				break
			if c != small[index]:
				break
			index += 1

		if index != 0:
			if largest_num == None:
				largest_num = len(large)
				print(large)
				i = j
			elif len(large) > largest_num:
				largest_num = len(large)
				i = j
	return i

def get_bits_from_addr(addresses):
	networks = []
	for address in addresses:
		if address != None:
		    ip_bin = convert_ips_to_binary(address)
		    networks.append(ip_bin[0:32])
		else:
			networks.append(None)
	return networks

def get_closest_ip(current_switch, target_ip):
	addresses = []

	for switch in current_switch.connected_switches:
		if switch.src_ip == current_switch.last_received_ip:
			addresses.append(None)
		else:
			addresses.append(switch.src_ip)

	bit_addresses = get_bits_from_addr(addresses)
	index = match_ips(target_ip, bit_addresses)
	return current_switch.connected_switches[index]


def parse_data(data, current_switch):
	# Ignore no data
	if len(data) == 0:
		return
	if data[11] == LOCATION:
		current_switch.update_distance(calculate_distance(data, current_switch))

	elif data[11] == DISTANCE:
		src_ip = socket.inet_ntoa(data[0:4])
		target_ip = socket.inet_ntoa(data[12:16])
		distance = int.from_bytes(data[16:20], byteorder='big')
		# Ignore packet if distance > 1000
		if distance > 1000:
			return

		current_switch.update_distance(distance)

		for switch in current_switch.connected_switches:
			if switch.src_ip == src_ip:
				switch.update_map(target_ip,  distance)
			elif switch.src_ip != src_ip and target_ip != switch.src_ip and target_ip != switch.my_ip:
				if target_ip not in switch.distance_map or switch.distance_map[target_ip] == 1001:
					switch.update_map(target_ip, switch.distance + distance)

				switch.update_distance(distance)
				packet = utils.create_switch_packet(switch.my_ip, switch.src_ip, DISTANCE, target_ip, int(switch.distance))
				switch.sock.sendto(packet, (LOCALHOST, switch.port))

	elif data[11] == AVAILABLE:
		src_ip = socket.inet_ntoa(data[0:4])
		closest_switch = None
		for switch in current_switch.connected_switches:
			if switch.src_ip == src_ip:
				closest_switch = switch

		if closest_switch.lastest_packet != None:
			closest_switch.verified = True
			if closest_switch.verified_function != None:
				closest_switch.verified_function.cancel()

			closest_switch.verified_function = threading.Timer(5, toggle_verified, [closest_switch])
			closest_switch.verified_function.start()
			# Receive available, send the packet to send
			closest_switch.sock.sendto(closest_switch.lastest_packet, (LOCALHOST, closest_switch.port))
			closest_switch.lastest_packet = None
			current_switch.last_received_ip = closest_switch.src_ip

	elif data[11] == QUERY:
		chosen_switch = None
		src_ip = socket.inet_ntoa(data[0:4])
		dst_ip = socket.inet_ntoa(data[4:8])

		for switch in current_switch.connected_switches:
			if switch.src_ip == src_ip:
				chosen_switch = switch
				break

		# Send an available to the query
		# Create Available packet 
		packet = utils.create_adapter_packet(dst_ip, src_ip, AVAILABLE, EMPTY_IP, None)
		chosen_switch.sock.sendto(packet, (LOCALHOST, chosen_switch.port)) 

		# set the switch that sent it to be verified == True
		chosen_switch.verified = True
		if chosen_switch.verified_function != None:
			chosen_switch.verified_function.cancel()

		chosen_switch.verified_function = threading.Timer(5, toggle_verified, [chosen_switch])
		chosen_switch.verified_function.start()
		current_switch.last_received_ip = chosen_switch.src_ip

	elif data[11] == DATA or data[0][11] == MORE_FRAG or data[0][11] == END_FRAG:
		switch_utils.parse_data_packet((data, None), current_switch)











