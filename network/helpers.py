import ipaddress, socket, struct, random, re, os, netifaces, json

def nic(dst : ipaddress._IPAddressBase) -> ipaddress._IPAddressBase:

	gateways = netifaces.gateways()
	default_gateway = gateways['default'][socket.AF_INET][0]

	for gateway in [v for k, v in gateways.items() if type(v) == dict]:
			
		addr, iface = gateway.get(socket.AF_INET)

		if addr == default_gateway:
			
			for addresses in netifaces.ifaddresses(iface).get(socket.AF_INET):
				
				return ipaddress.ip_address(addresses['addr'])
	
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

def create_packet_syn(src_addr : ipaddress._BaseAddress, dst_addr : ipaddress._BaseAddress, src_port : int, dst_port : int):

	seq = 0
	ack = 0
	flags = 0x2
	length = 0x28
	window = 5840
	checksum = 0
	pointer = 0

	tmp_ip_header = struct.pack('!BBHHHBBH4s4s',
							(src_addr.version << 4) + 5, 0,
							length, os.getpid() & 0xffff,
							0, 255,
							socket.IPPROTO_TCP, checksum,
							src_addr.packed, dst_addr.packed)
	
	ip_header = struct.pack('!BBHHHBBH4s4s',
							(src_addr.version << 4) + 5, 0,
							0x28, os.getpid() & 0xffff,
							0, 255,
							socket.IPPROTO_TCP, calculate_checksum(tmp_ip_header),
							src_addr.packed, dst_addr.packed)

	tmp_tcp_header = struct.pack('!HHLLBBHHH',
							 src_port, dst_port,
							 seq, ack, (5 << 4) + 0,
							 flags, window,
							 checksum, pointer)

	pseudo_header = struct.pack('!4s4sBBH', src_addr.packed, dst_addr.packed, 0, socket.IPPROTO_TCP, len(tmp_tcp_header))
	checksum = calculate_checksum(pseudo_header + tmp_tcp_header)

	tcp_header = struct.pack('!HHLLBBHHH',
							 src_port, dst_port,
							 seq, ack, (5 << 4) + 0,
							 flags, window,
							 checksum, pointer)

	return ip_header + tcp_header
	