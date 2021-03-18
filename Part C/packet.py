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

def flag_sum(flags):
	total = 0
	for flag in flags:
		total += flag_nums[flag]
	return total

def create_packet(sequence_num, ack_num, flags, payload, checksum = 0):
	last_header = 2
	packet = sequence_num.to_bytes(2, "big")
	packet += ack_num.to_bytes(2, "big")

	packet += checksum.to_bytes(2, "big")
	packet += flag_sum(flags).to_bytes(1, "big")
	packet += last_header.to_bytes(1, "big")

	packet += payload
	return packet




