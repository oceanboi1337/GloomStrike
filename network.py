import socket, struct, os, threading, select, ipaddress, time, enum
from scapy.all import srp, Ether, ARP
from collections import defaultdict

class Protocol(enum.Enum):
    ICMP = 0
    ARP = 1
    TCP = 2
    UDP = 3

class NetworkMapper:
    def __init__(self, db : str=None) -> None:
        self.db = db
        self.icmp_sequence = 1
        self.threads = []
        self.verbose = 0
        self.results = dict()

    def create_icmp_packet(self):
        
        tmp_packet = struct.pack('bbHHh', 8, 0, 0, os.getpid() & 0xffff, self.icmp_sequence)
        packet = struct.unpack(f'!%dH' % (len(tmp_packet) // 2), tmp_packet)

        checksum = sum(packet)
        carry = checksum >> 16

        while carry:
            checksum = (checksum & 0xffff) + carry
            carry = checksum & 0xff

        checksum = ~checksum & 0xffff

        packet = struct.pack('bbHHh', 8, 0, socket.htons(checksum), os.getpid() & 0xffff, self.icmp_sequence)
        self.icmp_sequence += 1

        return packet
    
    def ip2hostname(self, host : str):

        try:
            hostname = socket.getnameinfo((str(host), 0), 0)
            return hostname
        except Exception as e:
            print(f'[ERROR]: Failed to get hostname for {host}')

    def icmp_receiver(self, s : socket.socket, event : threading.Event):

        while 1:

            if event.is_set():
                break

            read, write, error = select.select([s], [], [], 0)

            if read:

                data, addr = s.recvfrom(1024)
                src = ipaddress.ip_address(addr[0])

                self.results[str(src)] = {'version': src.version}

        for host in self.results.keys():
            
            if hostname := self.ip2hostname(str(host)):
                self.results[str(host)]['hostname'] = hostname[0]

    def icmp_discover(self, network : ipaddress.IPv4Network | ipaddress.IPv6Network):

        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

        event = threading.Event()

        thread = threading.Thread(target=self.icmp_receiver, args=[s, event])
        thread.start()

        for retry in range(2):

            for host in network.hosts():

                try:

                    packet = self.create_icmp_packet()
                    endpoint = (str(host), 0) # IPAddress, Port

                    s.sendto(packet, endpoint)

                except Exception as e:
                    print(f'[ERROR]: Failed to send packet to {host}: {e}')
                    
            time.sleep(0.5)

        start = time.time()

        try:

            while not event.is_set():

                time.sleep(0.01) # Sleep to prevent CPU dying

                if time.time() - start > 3: # Stop listening for ICMP responses after 3 seconds
                    break

        except KeyboardInterrupt as e:
            print('[INFO]: Stopping threads...')

        event.set()
        thread.join()

        return self.results

    def arp_discover(self, network : ipaddress.IPv4Network | ipaddress.IPv6Network):

        hosts = [str(x) for x in network.hosts()]

        print(f'[INFO]: Sending ARP packets...')
        answers, unanswered = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=hosts), timeout=3, verbose=0, promisc=False)

        print(f'[INFO]: Processing {len(answers)} answers')
        for send, recv in answers:

            mac = recv.hwsrc
            src = ipaddress.ip_address(recv.psrc)
            hostname= self.ip2hostname(str(src))

            self.results[str(src)] = {'mac': mac, 'hostname': hostname[0] if hostname else None, 'version': src.version}

        return self.results

    def discover(self, cidr : str, protocol : Protocol):

        network = None

        try:
            network = ipaddress.IPv4Network(cidr)
        except ValueError as e:
            print(f'[ERROR]: Invalid CIDR ({cidr}): {e}')
            return
        
        if protocol == Protocol.ICMP:
            return self.icmp_discover(network)
        elif protocol == Protocol.ARP:
            return self.arp_discover(network)

    def port_scan_tcp(self, host : str, ports : list[int]):

        result = []

        for port in ports:

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)

            if not s.connect_ex((host, port)):
                continue

            ports.append({'port': port, 'protocol': 'tcp', 'status': True})


    def port_scan(self, host : str, ports : list[int], protocol : Protocol=Protocol.ARP):

        result = None

        match protocol:

            case Protocol.TCP:
                result = self.port_scan_tcp(host, ports)
            case Protocol.UDP: 
                result = self.port_scan_udp(host, ports)