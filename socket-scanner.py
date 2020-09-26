import socket
import time
import sys
import getopt
import re

config = {
	"targetIp": "", 
	"targetPort": "",
	"targetPortRange": []
}

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
	socket.setdefaulttimeout(0.15)
	s = socket.socket()
	res = s.connect_ex((host, port))
	s.close()
	return res

def main(argv):
	start = time.time()
	try:
		opts, _ = getopt.getopt(
			argv, "hi:p:P:", ["ip=", "port=", "portRange="])
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
	if  bool(re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", config["targetIp"])) != True:
		printUsage()
		print("\nInvalid IP provided. Exiting..")
		sys.exit(1)
	if config["targetPort"] != '' and config["targetPortRange"] != []:
		printUsage()
		print("\nYou cannot use both --port and --portRange arguments at the same time. Exiting..")
		sys.exit(1)
	if config["targetPort"] != '' and (isinstance(config["targetPort"], int) != True or int(config["targetPort"]) not in range(65535)):
		printUsage()
		print("\nInvalid Port number provided. Exiting..")
		sys.exit(1)
	if len(config["targetPortRange"]) != 0 and (len(config["targetPortRange"]) < 2 or len(config["targetPortRange"]) > 2 or  not isinstance(config["targetPortRange"][0], int) or not isinstance(config["targetPortRange"][1], int) or config["targetPortRange"][0]>=config["targetPortRange"][1] or config["targetPortRange"][0] not in range (65535) or config["targetPortRange"][1] not in range(65535)):
		printUsage()
		print("\nInvalid port range provided. Exiting..")
		sys.exit(1)

	# start scanning
	if config["targetPort"] != '':
		res = checkPort(config["targetIp"], int(config["targetPort"]))
		if res == 0:
			print("port", config["targetPort"], " is open on", config["targetIp"])
		else:
			print("port", config["targetPort"], "is closed on", config["targetIp"])
		end = time.time()
		print("Scan lasted:", end - start, "seconds")
	elif len(config["targetPortRange"])>0:
		for p in range(config["targetPortRange"][0], config["targetPortRange"][1]+1):
			res = checkPort(config["targetIp"], p)
			print(p, res)
			if res == 0:
				print("port", p, " is open")
		end = time.time()
		print("Scan duration:", end - start, "seconds")
	else:
		for p in range(65535):
			res = checkPort(config["targetIp"], p)
			print(p, res)
			if res == 0:
				print("port", p, " is open")
		end = time.time()
		print("Scan duration:", end - start, "seconds")

if __name__ == "__main__":
   main(sys.argv[1:])