import socket
import sys
 
LOCALHOST = "127.0.0.1"
 
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
	sock.bind((LOCALHOST, 0))
	sock.listen(1)                                           

	while True:
		print(sock.getsockname()[1])

		connection, client_address = sock.accept()      
		print("Got a connection from %s" % str(client_address))
	    
		try:
			print('connection from', client_address)
			# Receive the data in small chunks and retransmit it
			while True:
				data = connection.recv(16)
				print(data)
				if data:
					connection.sendall(data)
				else:
					print('no more data from {}'.format(client_address))
					break
		finally:
			# Clean up the connection
			msg = 'Thank you for connecting'+ "\r\n"
			connection.send(msg.encode('ascii'))
			connection.close()

except socket.error as msg:
	print('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
	sys.exit()
	
print('Socket bind complete')

