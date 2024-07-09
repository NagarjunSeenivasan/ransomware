import re, uuid
import socket
# joins elements of getnode() after each 2 digits.
# using regex expression
#print ("The MAC address in formatted and less complex way is : ", end="")
#print (':'.join(re.findall('..', '%012x' % uuid.getnode())))
mac=':'.join(re.findall('..', '%012x' % uuid.getnode()))
print(mac)


hostname = socket.gethostname()
IPAddr = socket.gethostbyname(hostname)
IP = socket.gethostbyname(hostname)
print(IP)
