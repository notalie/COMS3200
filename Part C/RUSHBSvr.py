import socket
import sys
 
LOCALHOST = "127.0.0.1"
 
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

sock.bind((LOCALHOST, 0))                                     
print(sock.getsockname()[1])

while True:
	data, address = sock.recvfrom(1500)
	print(data[0:8])






	if data.decode().rstrip() == 'go away':
		# Close the connection code
		msg = str.encode("Thank you for connecting\n")
		sock.sendto(msg, address)
		sock.close()
		break
	
print('Socket bind complete')

