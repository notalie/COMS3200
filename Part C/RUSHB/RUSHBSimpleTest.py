import sys
import subprocess
import time
import os

STARTUP_TIMEOUT = 10
RUN_TIMEOUT = 15
RUSHB_TESTSUITE_VERSION = '0.1'

def main(argv):
    print('RUSHB_TEST_VERSION: ' + RUSHB_TESTSUITE_VERSION)

    if len(argv) <= 1 or not argv[1].isdigit():
        print("Usage: python RUSHBSimpleTest.py client_port mode")
        return

    if os.path.isfile("makefile") or os.path.isfile("Makefile"):
        try:
            subprocess.check_output(["make"])
        except subprocess.CalledProcessError:
            print("Error occured when calling make.")
            return

    try:
        client_port = int(argv[1])
    except ValueError:
        print("Client port is invalid.")
        return

    mode = "SIMPLE"
    if len(argv) > 2:
        mode = argv[2]

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
        print("Found server on port " + str(serv_port) + ". Running the client...")
    except ValueError:
        print("Server port is invalid.")
        serv_proc.kill()
        return

    cli_proc = subprocess.Popen(["python3", "RUSHBSimpleClient.py", str(client_port), str(serv_port), "-m", mode, "-v", "9", "-o", mode+"_output.txt"])

    try:
        cli_proc.wait(timeout=RUN_TIMEOUT)
    except subprocess.TimeoutExpired:
        if mode.upper() == "INVALID_CHECKSUM_VAL":
            with open(mode + "_output.txt", "w") as f:
                f.close()
        else:
            print("\nTimeout exceeded during connection. Please use Wireshark to see what is missing.")
            cli_proc.kill()
            return

    if serv_proc.poll() is not None:
        serv_proc.kill()

    with open(mode+"_output.txt", "r") as f, open(os.path.join("test_files", mode + "_output.txt"), "r") as g:
        output = f.read()
        expected = g.read()
        if output == expected:
            print("\n[{}] is tested successfully. Output is as expected.".format(mode))
        else:
            print("\nDifferences in output detected.")
            print("Compare differences using diff {}_output.txt {}_output.txt".format(mode, os.path.join("test_files", mode)))

if __name__ == "__main__":
    main(sys.argv)
