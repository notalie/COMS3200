PAYLOAD_SIZE = 1463

def str_to_int(string, pad=PAYLOAD_SIZE):
    b_str = string
    if pad is not None:
        for i in range(len(string), pad):
            b_str += b'\0'
    return int.from_bytes(b_str, byteorder='big')


def int_to_bytes(integer, size=PAYLOAD_SIZE):
    return integer.to_bytes(size, byteorder='big').rstrip(b'\x00')

ENC_KEY = 11
DEC_KEY = 15
MOD = 249
def encode(payload, key=ENC_KEY, n=MOD):
    result = b""
    for c in payload:
    	value = (c ** key) % n
    	result += int_to_bytes(value ,1)
    return result

def get_encoded(CLIENT, payload):
	if CLIENT.requires_encryption:
		encoded_payload = encode(payload)
		# Add \x00 padding
		while len(encoded_payload) != PAYLOAD_SIZE + 1:
			padding = 0
			encoded_payload += padding.to_bytes(2, 'big') 
		return encoded_payload
	else:
		return payload

def decode(payload, key=DEC_KEY, n=MOD):
    message = ""
    int_message = 0
    for c in payload:
        value = (c ** key) % n
        if value <= 127:
        	message += chr(value)
        else:
        	return message
    return message

def get_empty_payload():
	empty_payload = bytearray()
	while len(empty_payload) !=  PAYLOAD_SIZE + 1:
		empty_payload.append(0)
	return empty_payload

def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)

def compute_checksum(message):
    b_str = message
    if len(b_str) % 2 == 1:
        b_str += b'\0'
    checksum = 0
    for i in range(0, len(b_str), 2):   
        w = b_str[i] + (b_str[i+1] << 8)
        checksum = carry_around_add(checksum, w)

    return ~checksum & 0xffff

def get_checksum(CLIENT, payload):
    if CLIENT.requires_checksum:
        return compute_checksum(payload)
    else:
        return 0

def get_flags(CLIENT, current):
	if CLIENT.requires_checksum:
		current.append("CHK")

	if CLIENT.requires_encryption:
		current.append("ENC")

	return current


def check_empty_payload(payload):
	for c in payload:
		if c != '\x00':
			return False
	return True


