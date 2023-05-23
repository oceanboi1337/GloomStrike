import struct, ipaddress, enum, network, os, socket

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

            packet = None
            checksum = 0

            for _ in range(2):

                tcp = struct.pack('!HHLLBBHHH',
                                self.src_port,
                                self.dst_port,
                                self._sequence,
                                self._ack, (5 << 4) + 0,
                                self._flags,
                                self._window,
                                checksum,
                                self._pointer)
                
                if checksum:

                    packet = tcp
                    break

                psh = struct.pack('!4s4sBBH',
                                self.ip_header.src.packed,
                                self.ip_header.dst.packed,
                                0,
                                socket.IPPROTO_TCP,
                                0x14)

                checksum = network.helpers.calculate_checksum(psh + tcp)

            return packet

        @property
        def src_port(self):
            return self._src_port

        @property
        def dst_port(self):
            return self._dst_port

        def is_flags_set(self, flags : int):
            return self._flags & flags == self._flags

ip = IPHeader()
ip.version = 4
ip.length = 20
ip.ttl = 255
ip.identifier = os.getpid() & 0xffff
ip._src = ipaddress.IPv4Address('192.168.1.189')
ip._dst = ipaddress.IPv4Address('192.168.1.1')

tcp = TcpHeader(ip_header=ip)
tcp._src_port = 1337
tcp._dst_port = 80
tcp._flags = Flags.SYN
tcp._window = 5840
tcp._window = 0x1337

print((ip.pack() + tcp.pack()).hex())