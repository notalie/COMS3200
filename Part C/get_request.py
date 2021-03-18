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


#data, address = sock.recvfrom(1500)
def parse_file(payload, sock, address, seq_num, ack_num):
	# previous sequence number that will be checked against the ack packets
	prev_seq_num = int.from_bytes(seq_num, byteorder="big")
	decoded_payload = payload.decode("utf-8").replace('\x00', '')
	try:
		file = open(decoded_payload, "rb")
		file_data = file.readlines()

		payload_data = []
		current_payload = bytearray()

		for i in range(0, len(file_data[0])):
			current_payload.append(file_data[0][i])
			if (i % PAYLOAD_SIZE == 0 and i != 0):
				payload_data.append(current_payload)
				current_payload = bytearray()

		file.close()

		while len(current_payload) !=  PAYLOAD_SIZE + 1:
			current_payload.append(0)

		payload_data.append(current_payload)

		# Send payload to client
		for payload in payload_data:
			packet_to_send = packet.create_packet(prev_seq_num, 
					int.from_bytes(ack_num, byteorder="big"), ["DAT"], payload)
			sock.sendto(packet_to_send, address)

			# Get data ACK from client
			data, address = sock.recvfrom(1500)
			SEQUENCE_NUMBER = data[0:2]
			ACK_NUMBER = data[2:4]
			CHECKSUM = data[4:5]
			FLAGS = "{:08b}".format(int(data[6]), 16)

			STATIC_HEADER = data[7]
			if (STATIC_HEADER != 2):
				break

			STATIC_HEADER = data[7]
			PAYLOAD = data[8:]
			# Because we have an ACK, check that the payload is empty
			if int.from_bytes(PAYLOAD, byteorder="big") != 0:
				break

			prev_seq_num += 1

			# Check that ACK num == pre_seq_num
			if FLAGS[ACK] == '1' and int.from_bytes(ACK_NUMBER, byteorder="big") == (prev_seq_num - 1) and FLAGS[DAT] == '1':
				continue
			else:
				break

		return prev_seq_num
	except Exception as e:
		# Send bye bye packet here
		t, o, tb = sys.exc_info()
		frame = os.path.split(tb.tb_frame.f_code.co_filename)[1]
		print(t, frame, tb.tb_lineno)
		sock.close()


def wait_for_send():
	data, address = sock.recvfrom(1600)

	SEQUENCE_NUMBER = data[0:1]

	ACK_NUMBER = data[2:3]

	CHECKSUM = data[4:5]
	FLAGS = "{:08b}".format(int(data[6]), 16)
