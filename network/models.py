import struct, ipaddress, enum, network, socket

class Flags(enum.IntEnum):
    FIN = 0x1
    SYN = 0x2
    RST = 0x4
    PSH = 0x8
    ACK = 0x10

class IPHeader:

    def __init__(self, data : bytes=None) -> None:

        self.data = data[0:20] if data else b'\0' * 20
        self.fields = struct.unpack('!BBHHHBBH4s4s', self.data)

        self.version = self.fields[0]
        self.tos = self.fields[1]
        self.length = self.fields[2]
        self.identifier = self.fields[3]
        self.flags = self.fields[4]
        self.ttl = self.fields[5]
        self.protocol = self.fields[6]
        self.checksum = self.fields[7]
        self._src = self.fields[8]
        self._dst = self.fields[9]

    def pack(self) -> bytes:

        packet = None
        checksum = 0

        for i in range(2):

            packet = struct.pack('!BBHHHBBH4s4s',
                                (self.src.version << 4) + 5, self.tos, self.length,
                                self.identifier, self.flags,
                                self.ttl, self.protocol, checksum,
                                self.src.packed,
                                self.dst.packed)

            if checksum:
                break

            checksum = network.helpers.calculate_checksum(packet)

        return packet

    @property
    def src(self):
        return ipaddress.ip_address(self._src)

    @property
    def dst(self):
        return ipaddress.ip_address(self._dst)

class TcpHeader:

        def __init__(self, data : bytes=None, ip_header : IPHeader=None) -> None:

            self.data = data[0:20] if data else b'\0' * 20
            self.fields = struct.unpack('!HHLLBBHHH', self.data)
            self.ip_header = ip_header

            self._src_port = self.fields[0]
            self._dst_port = self.fields[1]
            self._sequence = self.fields[2]
            self._ack = self.fields[3]
            self._offset = self.fields[4]
            self._flags = self.fields[5]
            self._window = self.fields[6]
            self._checksum = self.fields[7]
            self._pointer = self.fields[8]

        def pack(self):

            tcp = struct.pack('!HHLLBBHHH',
                            self.src_port,
                            self.dst_port,
                            self._sequence,
                            self._ack,
                            (5 << 4) + 0,
                            self._flags,
                            self._window,
                            self._checksum,
                            self._pointer)

            psh = struct.pack('!4s4sBBH',
                            self.ip_header.src.packed,
                            self.ip_header.dst.packed,
                            0,
                            socket.IPPROTO_TCP,
                            len(tcp))

            checksum = network.helpers.calculate_checksum(psh + tcp)

            tcp = struct.pack('!HHLLBBHHH',
                            self.src_port,
                            self.dst_port,
                            self._sequence,
                            self._ack,
                            (5 << 4) + 0,
                            self._flags,
                            self._window,
                            checksum,
                            self._pointer)

            return tcp

        @property
        def src_port(self):
            return self._src_port

        @property
        def dst_port(self):
            return self._dst_port

        def is_flags_set(self, flags : int):
            return self._flags & flags == self._flags
        
class IcmpHeader:

        def __init__(self, data : bytes=None, ip_header : IPHeader=None) -> None:

            self.data = data[0:20] if data else b'\0' * 8
            self.fields = struct.unpack('!bbHHh', self.data)

            self.type = self.data[0]
            self.code = self.data[1]
            self.checksum = self.data[2]
            self.id = self.data[3]

        def pack(self):
             
             icmp = struct.pack('!bbHHh', self.type, self.code, self.checksum, self.id, 1)

             checksum = network.helpers.calculate_checksum(icmp) & 0xffff

             return struct.pack('!bbHHh', self.type, self.code, checksum, self.id, 1)

