import ipaddress, threading, network, socket, sys, select, time, random, logging
import helpers
from logger import Logger
from collections import defaultdict
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # Fix for a scapy ipv4 - ipv6 mismatch warning bug
from scapy.all import sr1, IPv46, TCP

class PortScanner:

    def __init__(self, target : str, ports : str, logger : Logger=None) -> None:
        
        self.threads = []
        self.results = {}
        self.event = threading.Event()
        self._progress = 0
        self.retries = 0
        self.logger = logger

        if valid_target := network.helpers.is_valid_host(target):
            self.target : ipaddress._BaseAddress = valid_target
        else:
            self.logger.error(f'Invalid target "{target}"')

        if not ports:
            self.ports = [21, 22, 25, 53, 80, 110, 123, 443, 465, 631, 993, 995, 3306]
        elif ports == '-':
            self.ports = list(range(1, 65536))
        else:
            self.ports = [int(x) for x in ports.split(',')]

        if hasattr(self, 'target'):

            self.src = network.helpers.default_interface(self.target)
            self.src_port = random.randint(1, 65536)

        self.queue = helpers.QueueHandler(self.ports)

        self.ready = bool(
            hasattr(self, 'target') and
            hasattr(self, 'src')
        )

    @property
    def progress(self) -> int:
        return round((self._progress / ((self.queue.queue.maxsize * self.retries) + len(self.results) + 1)) * 100)

    def _syn_scan(self):

        while not self.event.is_set():

            for port in self.queue:

                # Skip the port if it has already been scanned
                if port in self.results:
                    continue

                if sys.platform == 'win32':
                    
                    ip_header = IPv46(dst=str(self.target))
                    tcp_header = TCP(sport=self.src_port, dport=port, flags='S')

                    if (packet := sr1(ip_header / tcp_header, timeout=self.timeout / 1000, verbose=0)) != None \
                    and packet.haslayer(TCP) and packet[TCP].flags == network.Flags.SYN | network.Flags.ACK and port not in self.results:

                        self.logger.info(f'Port {port} is open')

                        self.results[port] = {'state': 'open', 'service': 'unknown'}

                else:

                    ip = network.models.IPHeader()
                    ip.version = 4
                    ip.length = 0x28
                    ip.protocol = socket.IPPROTO_TCP
                    ip.ttl = 255
                    ip.identifier = os.getpid() & 0xffff
                    ip._src = self.src.packed
                    ip._dst = self.target.packed

                    tcp = network.models.TcpHeader(ip_header=ip)
                    tcp._src_port = self.src_port
                    tcp._dst_port = port
                    tcp._flags = network.Flags.SYN
                    tcp._window = 5840

                    packet = ip.pack() + tcp.pack()

                    try:
                        self.s.sendto(packet, (str(self.target), 0))
                    except Exception as e:
                        self.logger.error(f'Failed to send SYN packet {e}')

                self._progress += 1
                time.sleep(self.timeout / 1000)

    def _listener(self):

        while not self.event.is_set():

            read, write, error = select.select([self.s], [], [], 0)
            
            if not read:
                continue

            data, addr = self.s.recvfrom(1024)

            ip = network.models.IPHeader(data[0:20])
            tcp = network.models.TcpHeader(data[20:40])

            # Skip if the SYN+ACK response was already received for this port
            if tcp.src_port in self.results:
                continue

            # Filter out unwanted traffic
            if ip.src != self.target or tcp.dst_port != self.src_port:
                continue

            if tcp.is_flags_set(network.Flags.RST):
                continue

            if tcp.is_flags_set(network.Flags.ACK | network.Flags.SYN):

                port = int(tcp.src_port)

                self.logger.info(f'Port {port} is open')
                self.results[port] = {'state': 'open', 'service': 'unknown  '}

    def stop(self):
        self.event.set()

    def worker(self):

        self.logger.info('Calculating Average RTT...')

        self.timeout = network.helpers.avg_rtt(self.target)

        rtt = round(self.timeout - 100, 2)

        self.logger.info(f'Average RTT: {rtt} ms')

        for _ in range(15 if sys.platform == 'win32' else 1):

            thread = threading.Thread(target=self._syn_scan)
            thread.daemon = True
            thread.start()
            
            self.threads.append(thread)

        i = 0
        while i < self.retries:

            if self.queue.queue.empty():

                self.logger.info(f'Retry attempt {i + 1}')
                time.sleep((self.timeout / 1000) * 10)
                self.queue.reset()
                i += 1

            time.sleep(0.001)

        time.sleep(self.timeout)

        return self.results

    def scan(self, retries : int=3, background : bool=False):

        self.retries = retries
        
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