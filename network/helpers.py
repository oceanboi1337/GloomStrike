import ipaddress, socket, struct, random, re

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

def calculate_checksum(packet : bytes):
    checksum = sum(packet)
    carry = checksum >> 16

    while carry:
        checksum = (checksum & 0xffff) + carry
        carry = checksum & 0xff

    return ~checksum & 0xffff

def create_packet_syn(src : ipaddress._BaseAddress, dst : ipaddress._BaseAddress, port : int):

    src_port = random.randint(1, 65536)
    dst_port = port
    seq = 1
    ack = 0
    flags = 0x2
    window = 5840
    checksum = 0
    pointer = 0

    ip_header = struct.pack('!BBHHHBBH4s4s',
                            (src.version << 4) + 5, 0, 
                            0, 0,
                            0, 255,
                            socket.IPPROTO_TCP, 0,
                            src.packed, dst.packed)

    tcp_header = struct.pack('!HHLLBBHHH',
                             src_port, dst_port,
                             seq, ack, (5 << 4) + 0,
                             flags, window,
                             checksum, pointer)

    pseudo_header = struct.pack('!4s4sBBH', src.packed, dst.packed, 0, socket.IPPROTO_TCP, len(tcp_header))
    checksum = calculate_checksum(pseudo_header + tcp_header)

    tcp_header = struct.pack('!HHLLBBHHH',
                             src_port, dst_port,
                             seq, ack, (5 << 4) + 0,
                             flags, window,
                             checksum, pointer)

    return ip_header + tcp_header
    