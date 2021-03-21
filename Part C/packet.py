import struct

flag_nums = {
	"ACK": 128,
	"NAK": 64,
	"GET": 32,
	"DAT": 16,
	"FIN": 8,
	"CHK": 4,
	"ENC": 2
}

ACK = 0
NAK = 1
GET = 2
DAT = 3
FIN = 4
CHK = 5
ENC = 6

def flag_sum(flags):
	total = 0
	for flag in flags:
		total += flag_nums[flag]
	return total

def create_packet(sequence_num, ack_num, flags, payload, checksum):
	last_header = 2

	packet = sequence_num.to_bytes(2, "big")
	packet += ack_num.to_bytes(2, "big")

	packet += checksum.to_bytes(2, "big")
	packet += flag_sum(flags).to_bytes(1, "big")
	packet += last_header.to_bytes(1, "big")

	packet += payload
	return packet

class Packet():
	def __init__(self, data):
		self.seq_num = data[0:2]
		self.ack_num = data[2:4]
		self.checksum = data[4:6]
		self.flags = "{:08b}".format(int(data[6]), 16) 
		self.flags_raw = data[6]
		self.header_correct = data[7] == 2
		self.payload = data[8:]

		self.needs_checksum = self.flags[CHK] == '1'
		self.needs_encryption = self.flags[ENC] == '1'


class Client():
	def __init__(self, last_packet, sock, address, checksum, requires_encryption):
		self.remaining_payloads = [] # For get requests

		self.last_packet = last_packet

		self.seq_num = 1

		self.requires_checksum = int.from_bytes(checksum, byteorder="big") != 0
		self.requires_encryption = requires_encryption
		self.address = address
		self.socket = sock















