import struct, ipaddress, enum, socket
import gloomstrike.network as network

class Flags(enum.IntEnum):
    
    '''
    The different flags available in the TCP header.
    '''

    FIN = 0x1
    SYN = 0x2
    RST = 0x4
    PSH = 0x8
    ACK = 0x10

class IPHeader:

    '''
    Takes 20 bytes in the __init__ function and parses the IP header.
    If no data is passed, it can be used to create new IP headers by setting each attribute.

    Attributes:
        version (int): Sets the IP version to use.
        tos (int): Sets the TOS field.
        length (int): The length of the IP header.
        identifier (int): The ID of the packet.
        flags (int): The flags that can be set in the Flags enum.
        ttl (int): Time to live field.
        protocol (int): Which protocol to use.
        checksum (int): The checksum of the header, this will automatically be generated when calling the .pack method.
        _src (bytes): Sets the source address.
        _dst (bytes): Sest the destination address.
        src (ipaddress.IPv4Address | ipaddress.IPv6Address): Will return the source address as a ipaddress object.
        dst (ipaddress.IPv4Address | ipaddress.IPv6Address): Will return the destination address as a ipaddress object.

    Methods:
        pack(): Generates the checksum and converts the header to bytes.
    '''

    def __init__(self, data : bytes=None) -> None:

        '''
        Takes the first 20 bytes from a packet and parses the IP header.

        If no data is passed to the class, then the buffer will be filled with null bytes.
        '''

        self.data = data[0:20] if data else b'\0' * 20

        # ! Unpacks the data buffer using the network endian (big endian)
        # B = 1 bytes
        # H = Unsigned short 2 bytes
        # 4s = 4 byte char[]

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

        '''
        Generates the checksum of the header and returns the header in bytes.

        Returns:
            bytes: The IP Header in bytes.
        '''

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
        '''
        Returns the source address for the header.

        Returns:
            ipaddress.IPv4Address | ipaddress.IPv6Address: The source IP Address
        '''
        return ipaddress.ip_address(self._src)

    @property
    def dst(self):
        '''
        Returns the destination address for the header.

        Returns:
            ipaddress.IPv4Address | ipaddress.IPv6Address: The source IP Address
        '''
        return ipaddress.ip_address(self._dst)

class TcpHeader:

        '''
        Takes 20 bytes in the __init__ function and parses the TCP header.
        If no data is passed, it can be used to create new TCP headers by setting each attribute.

        Attributes:
            _src_port (int): The source port where the packet should be sent from.
            _dst_port (int): The port where the packet should arrive at.
            _sequence (int): The TCP sequence number.
            _offset (int): The offset between the header and the data:
            _flags (int): Takes a value from the network.Flags enum class (Flags.SYN | Flags.ACK).
            _window (int): Sets the window size.
            _checksum (int): The checksum will be calculated when calling the .pack() method.
            _pointer (int): Urgent pointer field.

        Methods:
            pack(): Generates the checksum and converts the header to bytes.
            is_flags_set(flags: network.Flags): Can take multiple flags and check if they are set after parsing a TCP header (network.Flags.SYN | network.flags.ACK).
        '''

        def __init__(self, data : bytes=None, ip_header : IPHeader=None) -> None:

            '''
            Takes the first 20 bytes from a packet and parses the TCP header.

            If no data is passed to the class, then the buffer will be filled with null bytes.
            '''

            self.data = data[0:20] if data else b'\0' * 20
            self.fields = struct.unpack('!HHLLBBHHH', self.data)
            self.ip_header = ip_header

            self._src_port = self.fields[0]
            self._dst_port = self.fields[1]
            self.sequence = self.fields[2]
            self.ack = self.fields[3]
            self.offset = self.fields[4]
            self.flags = self.fields[5]
            self.window = self.fields[6]
            self.checksum = self.fields[7]
            self.pointer = self.fields[8]

        def pack(self):

            '''
            Generates the checksum of the packet and returns the header in bytes.

            Returns:
                bytes: The TCP Header in bytes.
            '''

            # ! Unpacks the data buffer using the network endian (big endian)
            # B = 1 bytes
            # H = Unsigned short 2 bytes
            # L = unsigned long 4 bytes

            tcp = struct.pack('!HHLLBBHHH',
                            self.src_port,
                            self.dst_port,
                            self.sequence,
                            self.ack,
                            (5 << 4) + 0,
                            self.flags,
                            self.window,
                            self.checksum,
                            self.pointer)

            # Takes the first 12 bytes from the IP header, used only to calculate the checksum.
            psh = struct.pack('!4s4sBBH',
                            self.ip_header.src.packed,
                            self.ip_header.dst.packed,
                            0,
                            socket.IPPROTO_TCP,
                            len(tcp))

            checksum = network.helpers.calculate_checksum(psh + tcp)

            # Repacks the TCP header with the correct checksum.
            tcp = struct.pack('!HHLLBBHHH',
                            self.src_port,
                            self.dst_port,
                            self.sequence,
                            self.ack,
                            (5 << 4) + 0,
                            self.flags,
                            self.window,
                            checksum,
                            self.pointer)

            return tcp

        @property
        def src_port(self):
            '''
            Returns the source port where the packet should be sent from.
            '''
            return self._src_port

        @property
        def dst_port(self):
            '''
            Returns the destination port where the packet should be sent from.
            '''
            return self._dst_port

        def is_flags_set(self, flags : int):
            '''
            Checks if certain flags are set in the TCP header.

            Example: is_flags_set(network.Flags.SYN | network.Flags.ACK) will return True if both flags are set.

            Args:
                network.Flags: One or more flags to check.

            Returns:
                bool: Returns True if the flag is set or False if not.
            '''
            return self.flags & flags == self.flags
        
class IcmpHeader:

        '''
        Takes 8 bytes to parse into a ICMP header.
        If no data is passed, it can be used to create new ICMP headers by setting each attribute.
        
        Attributes:
            _type (int): The ICMP packet type.
            _code (int): ICMP code field.
            _checksum (int): The checksum of the packet.
            _id (int): Id of the packet.

        
        '''

        def __init__(self, data : bytes=None, ip_header : IPHeader=None) -> None:

            self.data = data[0:20] if data else b'\0' * 8
            self.fields = struct.unpack('!bbHHh', self.data)

            self.type = self.data[0]
            self.code = self.data[1]
            self.checksum = self.data[2]
            self.id = self.data[3]

        def pack(self):
             
            '''
            Generates the checksum of the packet and returns the header in bytes.

            Returns:
                bytes: The ICMP Header in bytes.
            '''
            
            # Temporary ICMP header
            icmp = struct.pack('!bbHHh', self.type, self.code, self.checksum, self.id, 1)

            checksum = network.helpers.calculate_checksum(icmp) & 0xffff

            # Reconstruct the ICMP header with the correct checksum
            return struct.pack('!bbHHh', self.type, self.code, checksum, self.id, 1)

