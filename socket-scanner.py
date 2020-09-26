import socket
import time
import sys
import getopt
import re

config = {"targetIp": "", "targetPort": "", "targetPortRange": []}
ports = []


class colors:
	GREEN = '\033[92m'
	RED = '\033[91m'
	BOLD = '\033[1m'
	END = '\033[0m'


def printUsage():
	'prints usage info'
	help = """Usage: python socket-scanner.py [-options]
	-i --ip			Host's IP address
	-p --port		Port number for single port scan
	-P --portRange		Port range to scan (eg 1000,1800)

	If no port or portRange arguments exist then it performs a default portscan on port range 0-65535
	It is not possible to have both -p and -P flags."""
	print(help)


def checkPort(host, port):
	"checks if a port is open or not"
	socket.setdefaulttimeout(0.05)
	s = socket.socket()
	res = s.connect_ex((host, port))
	s.close()
	return res


def printResult():
	"prints the results array of scanned ports"
	found = False
	for i in range(len(ports)):
		if ports[i]["status"] == 0:
			found = True
			print("port", ports[i]["port"],
				  "is " + colors.BOLD + colors.GREEN + "OPEN" + colors.END)

	if not found:
		print(colors.RED + "No open ports found!" + colors.END)

def main(argv):
	start = time.time()
	try:
		opts, _ = getopt.getopt(argv, "hi:p:P:",
								["ip=", "port=", "portRange="])
	except getopt.GetoptError:
		printUsage()
		sys.exit(2)
	for opt, arg in opts:
		if opt == '-h':
			printUsage()
			sys.exit()
		elif opt in ("-i", "--ip"):
			config["targetIp"] = str(arg)
		elif opt in ("-p", "--port"):
			try:
				config["targetPort"] = int(arg)
			except ValueError:
				printUsage()
				print("\nInvalid Port number provided. Exiting..")
				sys.exit(1)
		elif opt in ("-P", "--portRange"):
			prange = arg.split(",")
			newRange = []
			for p in prange:
				try:
					newRange.append(int(p))
				except ValueError:
					printUsage()
					print("\nInvalid Port range provided. Exiting..")
			config["targetPortRange"] = newRange

	#Perform needed sanity checks before scanning starts.
	if config["targetIp"] == None or config["targetIp"] == "":
		printUsage()
		print("\nNo IP provided. Exiting..")
		sys.exit(1)
	if bool(re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$",
					 config["targetIp"])) != True:
		printUsage()
		print("\nInvalid IP provided. Exiting..")
		sys.exit(1)
	if config["targetPort"] != '' and config["targetPortRange"] != []:
		printUsage()
		print(
			"\nYou cannot use both --port and --portRange arguments at the same time. Exiting.."
		)
		sys.exit(1)
	if config["targetPort"] != '' and (
			isinstance(config["targetPort"], int) != True
			or int(config["targetPort"]) not in range(65535)):
		printUsage()
		print("\nInvalid Port number provided. Exiting..")
		sys.exit(1)
	if len(config["targetPortRange"]) != 0 and (
			len(config["targetPortRange"]) < 2
			or len(config["targetPortRange"]) > 2
			or not isinstance(config["targetPortRange"][0], int)
			or not isinstance(config["targetPortRange"][1], int)
			or config["targetPortRange"][0] >= config["targetPortRange"][1]
			or config["targetPortRange"][0] not in range(65535)
			or config["targetPortRange"][1] not in range(65535)):
		printUsage()
		print("\nInvalid port range provided. Exiting..")
		sys.exit(1)

	# start scanning
	if config["targetPort"] != '':
		res = checkPort(config["targetIp"], int(config["targetPort"]))
		ports.append({"port": config["targetPort"], "status": res})
	elif len(config["targetPortRange"]) > 0:
		numberOfPortsToScan = config["targetPortRange"][1] - config[
			"targetPortRange"][0]
		counter = 0
		for p in range(config["targetPortRange"][0],
					   config["targetPortRange"][1] + 1):
			print("Progress: {}/{}".format(counter, numberOfPortsToScan),
				  end="\r",
				  flush=True)
			res = checkPort(config["targetIp"], p)
			ports.append({"port": p, "status": res})
			counter += 1
	else:
		for p in range(65535):
			print("Progress: {}/{}".format(p, 65535), end="\r", flush=True)
			res = checkPort(config["targetIp"], p)
			ports.append({"port": p, "status": res})
	print("\n")
	printResult()
	end = time.time()
	print("Scan duration:", end - start, "seconds")


if __name__ == "__main__":
	main(sys.argv[1:])
