from io import BytesIO
import os.path
import packet
import numpy
import math
import sys, os

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

def get_empty_payload():
	empty_payload = bytearray()
	while len(empty_payload) !=  PAYLOAD_SIZE + 1:
		empty_payload.append(0)
	return empty_payload

def parse_file(CLIENT, received_packet):
	seq_num = received_packet.seq_num
	ack_num = received_packet.ack_num
	payload = received_packet.payload

	decoded_payload = payload.decode("utf-8").replace('\x00', '')
	try:
		file = open(decoded_payload, "rb") # Read all bytes in file
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

		# Send first payload
		packet_to_send = packet.create_packet(int.from_bytes(seq_num, byteorder="big"), 0, ["DAT"], payload)
		CLIENT.socket.sendto(packet_to_send, CLIENT.address)
		CLIENT.last_packet = packet_to_send
		CLIENT.seq_num += 1

	except Exception as e:
		# error - > just exit lol
		t, o, tb = sys.exc_info()
		frame = os.path.split(tb.tb_frame.f_code.co_filename)[1]
		print(t, frame, tb.tb_lineno)


def send_data(CLIENT, data):

	# Because we have an ACK, check that the payload is empty
	if int.from_bytes(data.payload, byteorder="big") != 0:
		return

	# Check that ACK num == pre_seq_num
	if data.flags[ACK] != '1' or data.ack_num != CLIENT.last_packet[0:2] or data.flags[DAT] != '1':
		return

	try:
		payload = CLIENT.remaining_payloads.pop(0)

		# Send next payload only if the right variables are met
		packet_to_send = packet.create_packet(CLIENT.seq_num, 0, ["DAT"], payload)
		CLIENT.socket.sendto(packet_to_send, CLIENT.address)
		CLIENT.last_packet = packet_to_send
		CLIENT.seq_num += 1


	except IndexError: # No more payload left to send
		# Return if all payloads have been sent
		packet_to_send = packet.create_packet(CLIENT.seq_num, 0, ["FIN"], get_empty_payload())
		CLIENT.socket.sendto(packet_to_send, CLIENT.address)
		CLIENT.last_packet = packet_to_send
		CLIENT.seq_num += 1



