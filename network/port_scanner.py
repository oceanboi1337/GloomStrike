import ipaddress, threading, network, socket, sys, select
from helpers import QueueHandler
from collections import defaultdict

if sys.platform == 'win32':
    from scapy.all import sr1, IP, TCP

class PortScanner:

    def __init__(self, target : str, ports : str) -> None:
        
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
        elif ports == '-':
            self.ports = list(range(1, 65536))
        else:
            self.ports = [int(x) for x in ports.split(',')]

        self.queue = QueueHandler(self.ports)

    def tcp_scan(self, s : socket.socket):

        for port in self.queue:

            packet = network.create_packet_syn(ipaddress.ip_address('192.168.1.189'), self.target, port)

            s.sendto(packet, (str(self.target), 0))

    def listener(self, s : socket.socket):

        while 1:

            read, write, error = select.select([s], [], [], 0)

            if read:

                data, addr = s.recvfrom(1024)

                ip = network.models.IPHeader(data[0:20])
                tcp = network.models.TcpHeader(data[20:40])

                if ip.src != self.target or tcp.dst_port != 1337:
                    continue

                #print(tcp_header._offset, tcp_header._flags, data.hex())

                if tcp.is_flags_set(network.Flags.RST):
                    continue
                
                elif tcp.is_flags_set(network.Flags.ACK | network.Flags.SYN):
                    print(f'[INFO]: Port {tcp.src_port} is open')

    def start(self, threads : int=0):
        
        if sys.platform != 'win32':

            family = socket.AF_INET if self.target.version == 4 else socket.AF_INET6
            s = socket.socket(family, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            listener_thread = threading.Thread(target=self.listener, args=[s])
            listener_thread.start()

            if threads > 0:

                for tid in range(threads):

                    thread = threading.Thread(target=self.tcp_scan, args=[s])
                    thread.start()
                    
                    self.threads.append(thread)
            else:
                self.tcp_scan()