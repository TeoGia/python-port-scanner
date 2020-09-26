import socket

targetIp = "192.168.1.1"
targetPort = 80

socket.setdefaulttimeout(20)
s = socket.socket()
s.connect((targetIp, targetPort))

###
# First grab banner if any
###
banner = s.recv(2048)
print(banner)


###
# send arbitrary cmd
###
s.send(b'GET /\n\n')

###
# receive response data here
###
res = s.recv(2048)
print("Response:", res)
s.close()