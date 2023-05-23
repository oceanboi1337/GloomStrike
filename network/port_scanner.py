import ipaddress, threading, network, socket, sys, select, time, random, logging
import helpers
from collections import defaultdict
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # Fix for a scapy ipv4 - ipv6 mismatch warning bug
from scapy.all import *

if sys.platform == 'win32':
    from scapy.all import sr1, IPv46, TCP

class PortScanner:

    def __init__(self, target : str, ports : str, src_port : int=None) -> None:
        
        self.threads = []
        self.results = {}
        self.event = threading.Event()
        self._progress = 0
        self.retries = 0

        if '/' in target:
            self.target : ipaddress._BaseNetwork = network.helpers.is_valid_network(target)
        else:
            self.target : ipaddress._BaseAddress = network.helpers.is_valid_host(target)

        if self.target == None:
            print(f'[ERROR]: Invalid target {target}')

        if not ports:
            self.ports = [21, 22, 25, 53, 80, 110, 123, 443, 465, 631, 993, 995, 3306]
        elif ports == '-':
            self.ports = list(range(1, 65536))
        else:
            self.ports = [int(x) for x in ports.split(',')]

        self.src = network.helpers.nic(self.target)
        self.src_port = random.randint(1, 65536) if not src_port else src_port

        self.queue = helpers.QueueHandler(self.ports)

    @property
    def progress(self) -> int:
        return int((self._progress / ((self.queue.queue.maxsize * self.retries) - len(self.results))) * 100)

    def _syn_scan(self):

        while not self.event.is_set():

            for port in self.queue:

                if self.event.is_set():
                    break

                if port in self.results:
                    continue

                if sys.platform == 'win32':
                    
                    ip_header = IPv46(dst=str(self.target))
                    tcp_header = TCP(sport=self.src_port, dport=port, flags='S')
                    
                    if (packet := sr1(ip_header / tcp_header, timeout=1, verbose=0)) == None:
                        continue

                    if packet.haslayer(TCP) and packet[TCP].flags == 18 and port not in self.results:

                        print(f'[INFO]: Port {port} is open')

                        self.results[port] = {'state': 'open', 'service': 'unknown'}

                else:

                    packet = network.helpers.create_packet_syn(self.src, self.target, self.src_port, port)

                    try:

                        self.s.sendto(packet, (str(self.target), 0))
                        self._progress += 1

                    except Exception as e:
                        print(f'[ERROR]: Failed to send SYN packet', e)

                time.sleep(0.00001)

    def _listener(self):

        while not self.event.is_set():

            read, write, error = select.select([self.s], [], [], 0)
            
            if not read:
                continue

            data, addr = self.s.recvfrom(1024)

            ip = network.models.IPHeader(data[0:20])
            tcp = network.models.TcpHeader(data[20:40])

            if ip.src != self.target or tcp.dst_port != self.src_port:
                continue

            if tcp.is_flags_set(network.Flags.RST):
                continue

            if tcp.is_flags_set(network.Flags.ACK | network.Flags.SYN):

                port = int(tcp.src_port)

                print(f'[INFO]: Port {port} is open')

                if port not in self.results:
                    self.results[port] = {'state': 'open', 'service': 'unknown  '}

    def stop(self):
        self.event.set()

    def worker(self):

        for _ in range(15 if sys.platform == 'win32' else 1):

            thread = threading.Thread(target=self._syn_scan)
            thread.daemon = True
            thread.start()
            
            self.threads.append(thread)

        i = 0
        while i < self.retries:

            if self.queue.queue.empty():

                self.queue.reset()
                i += 1

            time.sleep(0.01)

        self.event.set()

        return self.results

    def scan(self, timeout : int=3, retries : int=3, background : bool=False):

        self.retries = retries
        self.timeout = timeout

        self.event.clear()

        if sys.platform != 'win32':

            family = socket.AF_INET if self.target.version == 4 else socket.AF_INET6
            
            self.s = socket.socket(family, socket.SOCK_RAW, socket.IPPROTO_TCP)
            self.s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            self.listener_thread = threading.Thread(target=self._listener)
            self.listener_thread.daemon = True
            self.listener_thread.start()

        if background:

            self.background_thread = threading.Thread(target=self.worker)
            self.background_thread.daemon = True
            self.background_thread.start()

            return self.results
        
        else:
            return self.worker()