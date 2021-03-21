from io import BytesIO
import os.path
import packet
import numpy
import math
import sys, os
import utils

PAYLOAD_SIZE = 1463

FLAGS = 6
LAST_BYTE = 7

ACK = 0
NAK = 1
GET = 2
DAT = 3
FIN = 4
CHK = 5
ENC = 6

def parse_file(CLIENT, received_packet):
	seq_num = received_packet.seq_num
	ack_num = received_packet.ack_num
	payload = received_packet.payload

	if not received_packet.needs_encryption:
		payload = payload.decode("utf-8").replace('\x00', '')
	else:
		payload = payload.replace('\x00', '')

	try:
		file = open(payload, "rb") # Read all bytes in file
		file_data = file.readlines()
		file.close()

		payload_data = []
		current_payload = bytearray()

		# Split data into small enough bytes for sending over multiple packets
		for i in range(0, len(file_data[0])):
			current_payload.append(file_data[0][i])
			if (i % PAYLOAD_SIZE == 0 and i != 0):
				payload_data.append(current_payload)
				current_payload = bytearray()

		# Padding with 0s
		while len(current_payload) != PAYLOAD_SIZE + 1:
			current_payload.append(0)

		payload_data.append(current_payload)

		# Add to our current packet
		CLIENT.remaining_payloads = payload_data
		payload = CLIENT.remaining_payloads.pop(0)

		flags = utils.get_flags(CLIENT, ["DAT"])
		payload = utils.get_encoded(CLIENT, payload)
		checksum = utils.get_checksum(CLIENT, payload)
		# Send first payload
		packet_to_send = packet.create_packet(int.from_bytes(seq_num, byteorder="big"), 0, 
				flags, payload, checksum)
		CLIENT.socket.sendto(packet_to_send, CLIENT.address)

		CLIENT.last_packet = packet_to_send
		CLIENT.seq_num += 1

	except Exception as e: # End connection if file cannot be found
		payload = utils.get_encoded(CLIENT, utils.get_empty_payload())
		checksum = utils.get_checksum(CLIENT, utils.get_empty_payload())

		flags = utils.get_flags(CLIENT, ["FIN"])
		packet_to_send = packet.create_packet(CLIENT.seq_num, 0, flags, payload, checksum)
		CLIENT.socket.sendto(packet_to_send, CLIENT.address)
		CLIENT.last_packet = packet_to_send
		CLIENT.seq_num += 1


def send_data(CLIENT, data):

	# Because we have an ACK, check that the payload is empty
	if CLIENT.requires_encryption and not utils.check_empty_payload(data.payload):
		return 
	elif not CLIENT.requires_encryption and int.from_bytes(data.payload, byteorder="big") != 0:
		return

	# Check that ACK num == pre_seq_num
	if data.flags[ACK] != '1' or data.ack_num != CLIENT.last_packet[0:2] or data.flags[DAT] != '1':
		return

	try: # Send next payload only if the right variables are met
		payload = CLIENT.remaining_payloads.pop(0)
		flags = utils.get_flags(CLIENT, ["DAT"])

		payload = utils.get_encoded(CLIENT, payload)
		checksum = utils.get_checksum(CLIENT, payload)

		packet_to_send = packet.create_packet(CLIENT.seq_num, 0, flags, payload, checksum)
		CLIENT.socket.sendto(packet_to_send, CLIENT.address)
		CLIENT.last_packet = packet_to_send
		CLIENT.seq_num += 1

	except IndexError: # No more payload left to send
		flags = utils.get_flags(CLIENT, ["FIN"])
		# Return if all payloads have been sent
		payload = utils.get_encoded(CLIENT, utils.get_empty_payload())
		checksum = utils.get_checksum(CLIENT, utils.get_empty_payload())

		packet_to_send = packet.create_packet(CLIENT.seq_num, 0, flags, payload, checksum)
		CLIENT.socket.sendto(packet_to_send, CLIENT.address)
		CLIENT.last_packet = packet_to_send
		CLIENT.seq_num += 1




