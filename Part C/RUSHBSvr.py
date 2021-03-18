import socket
import sys
import get_request
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
sock.bind((LOCALHOST, 0))                                     
print(sock.getsockname()[1], flush=True)

def get_empty_payload():
	empty_payload = bytearray()
	while len(empty_payload) !=  PAYLOAD_SIZE + 1:
		empty_payload.append(0)
	return empty_payload

def finish_connection(seq_num, ack_num, sock, addr):
	packet_to_send = packet.create_packet(seq_num, 
			int.from_bytes(ack_num, byteorder="big"), ["FIN"], get_empty_payload())
	sock.sendto(packet_to_send, addr)

	data, address = sock.recvfrom(1500)

	FLAGS = "{:08b}".format(int(data[6]), 16)
	SEQUENCE_NUMBER = data[0:2]
	ACK_NUMBER = data[2:4]

	if FLAGS == '10001000':
		packet_to_send = packet.create_packet(int.from_bytes(SEQUENCE_NUMBER, byteorder="big"), 
			int.from_bytes(SEQUENCE_NUMBER, byteorder="big"), ["FIN", "ACK"], get_empty_payload())
		sock.sendto(packet_to_send, address)


while True:
	data, address = sock.recvfrom(1500)

	SEQUENCE_NUMBER = data[0:2]
	ACK_NUMBER = data[2:4]
	CHECKSUM = data[4:6]
	FLAGS = "{:08b}".format(int(data[6]), 16)
	STATIC_HEADER = data[7]
	if (STATIC_HEADER != 2):
		break

	STATIC_HEADER = data[7]
	PAYLOAD = data[8:]

	if FLAGS[GET] == '1':
		seq_num = get_request.parse_file(PAYLOAD, sock, address, SEQUENCE_NUMBER, ACK_NUMBER)
	elif FLAGS[DAT] == '1':
		print('got data back')
	elif FLAGS == NAK:
		pass
	else: # No flags/bad
		print('none of these flags')
		break
	finish_connection(seq_num, ACK_NUMBER, sock, address)

sock.close()
print('Socket bind complete')

