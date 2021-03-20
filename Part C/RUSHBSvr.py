import socket
import sys
import data_handling
import packet
 
LOCALHOST = "127.0.0.1"

FLAGS = 6
LAST_BYTE = 7
PAYLOAD_SIZE = 1463

ACK = 0
NAK = 1
GET = 2
DAT = 3
FIN = 4
CHK = 5
ENC = 6

def encrypt():
	encrypted = ''
	# for i in 

# Connect to socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# TODO: change 53430 to 0
sock.bind((LOCALHOST, 53430))                                     
print(sock.getsockname()[1], flush=True)

def get_empty_payload():
	empty_payload = bytearray()
	while len(empty_payload) !=  PAYLOAD_SIZE + 1:
		empty_payload.append(0)
	return empty_payload

def close_connection(CLIENT, received_packet):
	packet_to_send = packet.create_packet(CLIENT.seq_num, 
			int.from_bytes(received_packet.seq_num, byteorder="big"), ["FIN", "ACK"], get_empty_payload())
	CLIENT.socket.sendto(packet_to_send, CLIENT.address)

def resend_data(CLIENT):
	CLIENT.socket.sendto(CLIENT.last_packet, CLIENT.address)

def parse_data(CLIENT, sock, address, received_packet):
	if received_packet.flags[GET] == '1': # [GET]
		data_handling.parse_file(CLIENT, received_packet)
	elif received_packet.flags[DAT] == '1' and received_packet.flags[ACK] == '1': # [DAT/ACK]
		data_sent = data_handling.send_data(CLIENT, received_packet)
	elif received_packet.flags[FIN] == '1' and received_packet.flags[ACK] == '1': # [FIN/ACK]
		close_connection(CLIENT, received_packet)
	elif received_packet.flags[NAK] == '1':
		resend_data(CLIENT)
	else: # No flags/bad - to do for checking later
		print('none of these')
		# finish_connection(CLIENT, received_packet)

# Address : Client
CLIENT_TRACKER = {}

while True:
	data, address = sock.recvfrom(1500)
	received_packet = packet.Packet(data)

	if address in CLIENT_TRACKER:
		CLIENT = CLIENT_TRACKER[address]
	else:
		CLIENT = packet.Client(received_packet, sock, address)
		CLIENT_TRACKER[address] = CLIENT


	# 8th byte is not equal to 2
	if received_packet.header_correct == False:
		finish_connection(CLIENT.seq_num, CLIENT.ack_num, sock, address)
	else:
		parse_data(CLIENT, sock, address, received_packet)

	


