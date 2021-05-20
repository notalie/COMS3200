import sys
import switch_utils
import threading

RECVSIZE = 2048 

current_switch = None

if sys.argv[1] == "local" and len(sys.argv) == 5:
	current_switch = switch_utils.Switch(True, False)
	current_switch.set_local_info(sys.argv[2])
elif sys.argv[1] == "local" and len(sys.argv) == 6: # Connected to both
	current_switch = switch_utils.Switch(True, True)
	current_switch.set_local_info(sys.argv[2])
	current_switch.set_global_info(sys.argv[3])
else: # Global switch
	current_switch = switch_utils.Switch(False, True)
	current_switch.set_global_info(sys.argv[2])

current_switch.x_pos = sys.argv[-2]
current_switch.y_pos = sys.argv[-1]

current_switch.initialise_ports()

# For debugging when using the `RUSHB.py` tests
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


 # Switch - Adapter connection
def udp_thread():
	while True:
		data = current_switch.local_sock.recvfrom(RECVSIZE)
		switch_utils.parse_data(data, current_switch)

# Swich - Switch connection
def tcp_thread():
	conn, addr = current_switch.global_sock.accept()
	while True:
		try:	
			data = conn.recvfrom(RECVSIZE)
			switch_utils.parse_switch_data(data, current_switch, addr[1], conn)
		except ConnectionResetError:
			pass

def read_stdin():
	# Accept stdin
	try:
		while True:
			data = input()
			if data.split(" ")[0] == 'connect':
				switch_utils.greeting_protocol(current_switch, data.split(" ")[1]) 
	except EOFError: 
		sys.exit() # Stop receiving stdin in an EOF
   	
# Create threads for each connection
if sys.argv[1] == "local" and len(sys.argv) == 5: # Local switch
	stdin_thread = threading.Thread(target=read_stdin, args=[])
	stdin_thread.start()
	local_thread = threading.Thread(target=udp_thread, args=[])
	local_thread.start()
elif sys.argv[1] == "local" and len(sys.argv) == 6: # Connected to both
	local_thread = threading.Thread(target=udp_thread, args=[])
	global_thread = threading.Thread(target=tcp_thread, args=[])	
	global_thread.start()
	local_thread.start()
else: # Global Switch
	stdin_thread = threading.Thread(target=read_stdin, args=[])
	stdin_thread.start()
	global_thread = threading.Thread(target=tcp_thread, args=[])	
	global_thread.start()
	





















