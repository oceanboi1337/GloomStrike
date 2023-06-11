import ipaddress, socket, struct, enum, re, os, socket, time, requests
from gloomstrike.network import models
from gloomstrike import logger
from scapy.all import sr1, IP, UDP, DNS, DNSQR, DNSRR


class Protocol(enum.IntEnum):
    ARP = 0
    ICMP = 1

def device_lookup(mac : str) -> str | None:

    '''
    Looks up the manufacturer of a MAC address.

    Sends a GET request to https://macvendors.com/query/{mac} which returns the manufacturer.

    Args:
        mac (str): The MAC address to lookup.

    Returns:
        str: The manufacturer of a device.
        None: Returns None if the MAC address had to results.
    '''
    
    try:

        resp = requests.get(f'https://macvendors.com/query/{mac}')

        if resp.ok:
            return resp.text if resp.text != 'Not Found' else None
        
    except Exception as e:
        return None

def nslookup(host : str, reverse : bool=False) -> str:

    '''
    Resolved a domain to a IP Address or sends a DNS request to the default gateway.

    Uses socket.getaddrinfo() to resolve a hostname to the IP Address.

    Uses Scapy's DNS API to send a reverse DNS request to resolve ip-address.ptr

    Args:
        host (str): The hostname to lookup.
        reverse (bool): Will make a reverse DNS PTR lookup if True.

    Returns:
        ipaddress._IPAddressBase: The result of the either lookup.
        None: Returns None if the lookup failed.
    '''

    try: 

        if reverse:

            ip = IP(dst='192.168.1.1') # Fix later to dynamically fetch the default gateway
            dns = DNS(rd=1, qd=DNSQR(qname=host.reverse_pointer, qtype='PTR'))

            response = sr1(ip / UDP() / dns, verbose=0, promisc=False)
            
            if DNSRR not in response[DNS]:
                return None

            return response[DNS][DNSRR].rdata.decode()
            
        else:

            return ipaddress.ip_address(socket.getaddrinfo(host, 0)[0][4][0])
        
    except Exception as e:
        return None

def ping(dst : ipaddress._IPAddressBase) -> int:

    '''
    Sends a ICMP Request and waits for a reply.

    Manually constructs the IP/ICMP headers to send the request.

    It will send the packet from the default interface. Not reliable over VPN connections.

    Args:
        dst (ipaddress._IPAddressBase) The IP Address to ping.

    Returns:
        int: The time in miliseconds it took from request to reply.
        None: Returns None if the packet failed to send.
    '''

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.settimeout(3)

    src = default_interface(dst)

    if not src:
        return None

    ip = models.IPHeader()
    ip.version = 4
    ip.length = 0x1c
    ip.protocol = socket.IPPROTO_ICMP
    ip.ttl = 255
    ip.identifier = os.getpid() & 0xffff
    ip._src = src.packed
    ip._dst = dst.packed

    icmp = models.IcmpHeader()
    icmp.type = 8
    icmp.code = 0
    icmp.id = os.getpid() & 0xffff

    s.sendto(ip.pack() + icmp.pack(), (str(dst), 0))

    start = time.time()
    try:
        data, addr = s.recvfrom(1024) # Add timeout later
    except TimeoutError:
        logger.log('Ping timed out', level=logger.Level.ERROR)
    s.close()

    # Subtracts now - start and multiply by 1000 to get the milisecond value,
    return int((time.time() - start) * 1000)

def avg_rtt(dst : ipaddress._IPAddressBase, rounds : int=10):

    '''
    Calculates the average round-trip-time to a host.

    Sends rounds amount of ICMP requests and calculate the average response time.

    Args:
        dst (ipaddress._IPAddressBase): The destination host to ping.
        rounds (int): How many times to ping.

    Returns:
        int: The average round-trip-time in miliseconds.
    '''

    total_rtt = 0

    for _ in range(rounds):

        total_rtt += ping(dst)

    return round((total_rtt / rounds), 2) # Rounds the decimal point to 2 places

def default_interface(dst : ipaddress._IPAddressBase=None) -> ipaddress._IPAddressBase:

    '''
    Returns the IP Address of the network interface that is being used.

    Uses a DGRAM socket to setup a connection to a target to determine the IP Address.

    Args:
        dst (ipaddress._IPAddressBase): Which host to setup the connection to (Optional).

    Returns:
        ipaddress._IPAddressBase: The IP Address of the default network interface.
        None: Returns None if the IP Address could not be determined.
    '''

    family = socket.AF_INET
    test_target = '1.1.1.1' # Uses 1.1.1.1 as the default test.

    if dst:

        # Sets the socket family to IPv4 or IPv6 based on the target's address type.
        family = socket.AF_INET if dst.version == 4 else socket.AF_INET6
        test_target = str(dst)

    # Sets up a a DGRAM socket, this does not result in any packets being sent.
    # It is only used to determine the local IPAddress that packets is being sent from.
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.connect((test_target, 80))

    if host := is_valid_host(s.getsockname()[0]):
        return host

    return None
    
def is_valid_domain(domain : str) -> bool:

    '''
    Uses regex matching to validate a domain name.

    ^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$

    Args:
        domain (str): The domain to check.

    Returns:
        bool: Returns True if the domain is valid and False if its invalid.
    '''

    r = re.compile('^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$')
    return bool(r.match(domain))

def is_valid_host(host : str) -> ipaddress._IPAddressBase:

    '''
    Checks if the Hostname / IP Address is valid.

    Will try convert the host to a IP Address.

    It will fallback and try resolve the host to a IP Address if its not a valid IP Address.

    Args:
        host (str): The host to validate.

    Returns:
        ipaddress._IPAddressBase: If the check is successful.
        None: Returns None if the check fails.
    '''

    try:

        return ipaddress.ip_address(host)
    
    except:

        if is_valid_domain(host):

            try:

                return nslookup(host)
            
            except Exception as e:
                return None
    
def is_valid_network(network : str):

    '''
    Checks if a CIDR is valid.

    Returns a iterable IP Address network.

    Args:
        network (str): The CIDR to validate, 192.168.1.0/24.

    Returns:
        ipaddress.IPv4Network or ipaddress.IPv6Network object.
    '''

    try:
        return ipaddress.ip_network(network)
    except:
        return None

def calculate_checksum(packet : bytes) -> int:

    '''
    Calcuates the checksum of a packet.

    Args:
        packet (bytes): The packet in bytes format.

    Returns:
        int: The checksum of the packet.
    '''

    if len(packet) % 2 == 1:
        packet += b'\0'

    data = struct.unpack('!%dH' % (len(packet) // 2), packet)
    
    checksum = sum(data)
    checksum += (checksum & 0xffff >> 16)
    checksum += (checksum >> 16)

    return ~checksum & 0xffff
