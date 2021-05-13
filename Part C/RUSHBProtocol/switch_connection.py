import utils
import math
import sys
import socket
from threading import Timer

LOCALHOST = "127.0.0.1"

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

def toggle_verified(current_switch):
	current_switch.verified = False


def parse_data(data, current_switch):
	# Ignore no data
	if len(data) == 0:
		return
	if data[11] == LOCATION:
		switch_ip = socket.inet_ntoa(data[0:4])
		current_switch.update_distance(calculate_distance(data, current_switch))

	elif data[11] == DISTANCE:
		src_ip = socket.inet_ntoa(data[0:4])
		target_ip = socket.inet_ntoa(data[12:16])
		eprint("src ip: {}".format(src_ip))

		eprint("target ip: {}".format(target_ip))
		distance = int.from_bytes(data[16:20], byteorder='big')
		# Ignore packet if distance > 1000
		if distance > 1000:
			return

		current_switch.update_distance(distance)

		for switch in current_switch.connected_switches:
			if switch.src_ip == src_ip:
				switch.update_map(target_ip,  distance)
			elif switch.src_ip != src_ip and target_ip != switch.src_ip and target_ip != switch.my_ip:
				if target_ip not in switch.distance_map:
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
			closest_switch.verified_function = Timer(5, toggle_verified, [current_switch])
			closest_switch.verified_function.start()
			# Receive available, send the packet to send
			closest_switch.sock.sendto(closest_switch.lastest_packet, (LOCALHOST, closest_switch.port))
			closest_switch.lastest_packet = None




















