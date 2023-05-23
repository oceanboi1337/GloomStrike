import struct, socket

s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind()
