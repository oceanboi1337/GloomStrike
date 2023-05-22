import ipaddress, socket, struct, random, re, os

def nic(dst : ipaddress._IPAddressBase) -> ipaddress._IPAddressBase:

    family = socket.AF_INET if dst.version == 4 else socket.AF_INET6
    #network = ipaddress.ip_network(dst)
    interfaces = socket.getaddrinfo(socket.gethostname(), None, family, 1, 0)

    print(interfaces)
    return ipaddress.ip_address(interfaces[0][0])

    """for family, sock_type, protocol, flags, addr in interfaces:

        src = ipaddress.ip_address(addr[0])
    """

def is_valid_domain(domain : str):

    r = re.compile('^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$')
    return r.match(domain)

def is_valid_host(host : str):

    try:
        return ipaddress.ip_address(host)
    except:
        if is_valid_domain(host):
            try:
                addr = socket.getaddrinfo(host, 0)
                return is_valid_host(addr[0][4][0])
            except Exception as e:
                print(f'[ERROR]: Failed to resolve {host}', e)
    
def is_valid_network(network : str):

    try:
        return ipaddress.ip_network(network)
    except:
        pass

def calculate_checksum(packet):

    if len(packet) % 2 == 1:
        packet += b'\0'

    data = struct.unpack('!%dH' % (len(packet) // 2), packet)
    
    checksum = sum(data)
    checksum += (checksum & 0xffff >> 16)
    checksum += (checksum >> 16)

    return ~checksum & 0xffff

def create_packet_syn(src : ipaddress._BaseAddress, dst : ipaddress._BaseAddress, port : int):

    src_port = 1337
    dst_port = port
    seq = 0
    ack = 0
    flags = 0x2
    length = 0x28
    window = 5840
    checksum = 0
    pointer = 0

    tmp_ip_header = struct.pack('!BBHHHBBH4s4s',
                            (src.version << 4) + 5, 0,
                            length, os.getpid() & 0xffff,
                            0, 255,
                            socket.IPPROTO_TCP, checksum,
                            src.packed, dst.packed)
    
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            (src.version << 4) + 5, 0,
                            0x28, os.getpid() & 0xffff,
                            0, 255,
                            socket.IPPROTO_TCP, calculate_checksum(tmp_ip_header),
                            src.packed, dst.packed)

    tmp_tcp_header = struct.pack('!HHLLBBHHH',
                             src_port, dst_port,
                             seq, ack, (5 << 4) + 0,
                             flags, window,
                             checksum, pointer)

    pseudo_header = struct.pack('!4s4sBBH', src.packed, dst.packed, 0, socket.IPPROTO_TCP, len(tmp_tcp_header))
    checksum = calculate_checksum(pseudo_header + tmp_tcp_header)

    tcp_header = struct.pack('!HHLLBBHHH',
                             src_port, dst_port,
                             seq, ack, (5 << 4) + 0,
                             flags, window,
                             checksum, pointer)

    return ip_header + tcp_header
    