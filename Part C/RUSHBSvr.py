import socket
import sys
import data_handling
import packet
from threading import Timer
import utils
 
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

# Connect to socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# TODO: change 53734 to 0
sock.bind((LOCALHOST, 0))                                     
print(sock.getsockname()[1], flush=True)

'''
	CLIENT_TRACKER -> Address : [Client, Timer]
	TIMEOUTS
'''
CLIENT_TRACKER = {}

def close_connection(CLIENT, received_packet):
	flags = utils.get_flags(CLIENT, ["FIN", "ACK"])
	payload = utils.get_encoded(CLIENT, utils.get_empty_payload())
	checksum = utils.get_checksum(CLIENT, utils.get_empty_payload())

	packet_to_send = packet.create_packet(CLIENT.seq_num, int.from_bytes(received_packet.seq_num, byteorder="big"), 
		flags, payload, checksum)
	CLIENT.socket.sendto(packet_to_send, CLIENT.address)

def resend_data(CLIENT):
	CLIENT.socket.sendto(CLIENT.last_packet, CLIENT.address)

def add_packet_timer(CLIENT):
	CLIENT_TRACKER[CLIENT.address][1] = Timer(4, resend_data, [CLIENT])
	CLIENT_TRACKER[CLIENT.address][1].start()

'''
	FLAG PARSING
'''
def parse_data(CLIENT, sock, address, received_packet):
	if received_packet.flags[NAK] == '1':
		CLIENT_TRACKER[CLIENT.address][1].cancel()

	if received_packet.flags[CHK] == '1' and utils.get_checksum(CLIENT, received_packet.payload) != int.from_bytes(received_packet.checksum, byteorder='big'):
		# Invalid Checksum - ignore packet if CHK flag is enabled
		return
	elif int.from_bytes(received_packet.checksum, byteorder='big') != 0 and received_packet.flags[CHK] != '1':
		# Checksum value but flag not enabled
		return 

	# Decrypt payload here after checksum
	if received_packet.needs_encryption:
		received_packet.payload = utils.decode(received_packet.payload)    

	if received_packet.flags[GET] == '1': # [GET]
		if len(CLIENT.remaining_payloads) != 0:
			CLIENT.client_seq_num -= 1
			CLIENT_TRACKER[CLIENT.address][1].cancel() # Cancel and reset send timer
		else:
			data_handling.parse_file(CLIENT, received_packet)
	elif received_packet.flags[DAT] == '1' and received_packet.flags[ACK] == '1': # [DAT/ACK]
		data_sent = data_handling.send_data(CLIENT, received_packet)
		if data_sent == False:
			CLIENT.client_seq_num -= 1
			CLIENT_TRACKER[CLIENT.address][1].cancel() # Cancel and reset send timer

	elif received_packet.flags[FIN] == '1' and received_packet.flags[ACK] == '1': # [FIN/ACK]
		close_connection(CLIENT, received_packet)
	elif received_packet.flags[NAK] == '1':
		resend_data(CLIENT)
	else: # No flags/bad - to do for checking later
		CLIENT.client_seq_num -= 1
		CLIENT_TRACKER[CLIENT.address][1].cancel() # Cancel and reset send timer

	add_packet_timer(CLIENT)

while True:
	data, address = sock.recvfrom(1500)
	received_packet = packet.Packet(data)

	if address in CLIENT_TRACKER:
		CLIENT = CLIENT_TRACKER[address][0]
	else:
		CLIENT = packet.Client(received_packet, sock, address, data[4:6], received_packet.needs_encryption)
		CLIENT_TRACKER[address] = [CLIENT, None]

	# Check sequence number is right
	if int.from_bytes(received_packet.seq_num, byteorder="big") == CLIENT.client_seq_num + 1:
		CLIENT.client_seq_num += 1
	elif int.from_bytes(received_packet.seq_num, byteorder="big") != CLIENT.client_seq_num + 1:
		# Sequence number is wrong or flags are wrong
		CLIENT_TRACKER[CLIENT.address][1].cancel()
		add_packet_timer(CLIENT)
		continue
	elif not received_packet.header_correct:
		# 8th byte is not equal to 2
		CLIENT_TRACKER[CLIENT.address][1].cancel()
		add_packet_timer(CLIENT)
		continue

	parse_data(CLIENT, sock, address, received_packet)

	
