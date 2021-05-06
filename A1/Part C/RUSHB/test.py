import sys
import subprocess
import os
import random
from threading import Timer

CLIENTS = 5

STARTUP_TIMEOUT = 10
RUN_TIMEOUT = 15
VALID_MODES = ["SIMPLE", "NAK", "MULTI_NAK", "TIMEOUT", "MULTI_TIMEOUT", "INVALID_SEQ", "INVALID_ACK", "INVALID_FLAGS",
                    "ENCODED", "CHECKSUM", "ENCODED_CHECKSUM", "INVALID_ENCODE_VAL", "INVALID_CHECKSUM_VAL",
                    "INVALID_ENCODE_FLAG", "INVALID_CHECKSUM_FLAG"]

RUSHB_TESTSUITE_VERSION = '0.6'
'''
0.1 - initial release
0.2 - fix bug on connecting client
0.3 - fix bug on invalid argument
0.4 - reduce port number on client
0.5 - fix bugs on large port number
1.0 - official sample test suit
'''

global flag


def timed():
    global flag
    flag = True


def main(argv):
    print('RUSHB_TEST_VERSION: ' + RUSHB_TESTSUITE_VERSION)

    if len(argv) < 1:
        print("Usage: python3 RUSHBSimpleTest.py mode")
        return

    if os.path.isfile("makefile") or os.path.isfile("Makefile"):
        try:
            subprocess.check_output(["make"])
        except subprocess.CalledProcessError:
            print("Error occured when calling make.")
            return

    mode = "SIMPLE"
    if len(argv) > 1 and argv[1] in VALID_MODES:
        mode = argv[1]
    else:
        print("Invalid mode, please check again. Now testing [SIMPLE] mode.")

    if os.path.isfile("RUSHBSvr.py"):
        call = ["python3", "RUSHBSvr.py"]
    elif os.path.isfile("RUSHBSvr.class"):
        call = ["java", "RUSHBSvr"]
    elif os.path.isfile("RUSHBSvr"):
        call = ["./RUSHBSvr"]
    else:
        print("No valid file found to call.")
        return

    serv_proc = subprocess.Popen(call, stdout=subprocess.PIPE)
    try:
        out = serv_proc.stdout.readline().decode("UTF-8")
        serv_port = int(out.partition("\n")[0].strip())
        print("Found server on port " + str(serv_port) + ".\nRunning the client...")
    except ValueError:
        print("Server port is invalid.")
        serv_proc.kill()
        return

    cli_procs = []
    client_port = random.randint(11111, 65534)
    # print("Selected client port is {}.".format(client_port))

    while len(cli_procs) <= CLIENTS:
        try:
            cli_proc = subprocess.Popen(["python3", "RUSHBSimpleClient.py", str(client_port), str(serv_port), "-m", mode, "-v", "9", "-o", mode+str(len(cli_procs))+"_output.txt"])
            cli_procs.append(cli_proc)
            client_port = random.randint(11111, 65534)
        except:
            client_port = random.randint(11111, 65534)
            print("Socket error found, change the client port to {}.".format(client_port))

    global flag

    flag = False
    t = Timer(RUN_TIMEOUT, timed)

    finished = [False for i in range(len(cli_procs))]

    t.start()

    while not flag:

        if not (False in finished):
            break

        for i in range(len(cli_procs)):
            if cli_procs[i].poll() is not None:
                finished[i] = True

    if not flag:
        t.cancel()
    else:
        for i in range(len(cli_procs)):
            poll = cli_procs[i].poll()

            if poll is None:
                print("\nTimeout exceeded during connection. Please use Wireshark to see what is missing.")
                cli_procs[i].kill()
                flag2 = True
        return

    if serv_proc.poll() is not None:
        serv_proc.kill()

    for i in range(len(cli_procs)):
        with open(mode + str(i) + "_output.txt", "r") as f, open(os.path.join("test_files", mode + "_output.txt"), "r") as g:
            output = f.read()
            expected = g.read()
            if output == expected:
                print("\n[{}] is tested successfully. Output is as expected.".format(mode))
            else:
                print("\nDifferences in output detected.")
                print("Compare differences using diff {}_output.txt {}_output.txt".format(mode + str(i),
                                                                                          os.path.join("test_files",
                                                                                                       mode)))


if __name__ == "__main__":
    main(sys.argv)
