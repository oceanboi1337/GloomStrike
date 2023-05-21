import ipaddress, threading, network, socket, sys|
from helpers import QueueHandler
from collections import defaultdict

if sys.platform

class PortScanner:

    def __init__(self, target : str, ports : list[int]=None) -> None:
        
        self.threads = []
        self.results = []

        if '/' in target:
            self.target : ipaddress._BaseNetwork = network.is_valid_network(target)
        else:
            self.target : ipaddress._BaseAddress = network.is_valid_host(target)

        if self.target == None:
            print(f'[ERROR]: Invalid target {target}')

        if not ports:
            self.ports = [21, 22, 25, 53, 80, 110, 123, 443, 465, 631, 993, 995, 3306]
        elif ports == []:
            self.ports = list(range(1, 65536))
        else:
            self.ports = ports

        self.queue = QueueHandler(self.ports)

    def tcp_scan(self, s : socket.socket):

        for port in self.queue:

            packet = network.create_packet_syn(ipaddress.ip_address('192.168.1.221'), self.target, port)
            print(packet.hex(), self.target, port)

            s.sendto(packet, (str(self.target), 0))

    def start(self, threads : int=0):
        
        family = socket.AF_INET if self.target.version == 4 else socket.AF_INET6
        s = socket.socket(family, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        if threads > 0:

            for tid in range(threads):

                thread = threading.Thread(target=self.tcp_scan, args=[s])
                thread.start()
                
                self.threads.append(thread)
        else:
            self.tcp_scan()