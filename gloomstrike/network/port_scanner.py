import ipaddress, threading, socket, sys, select, time, random, logging, os
from gloomstrike import logger, helpers, network
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # Fix for a scapy ipv4 - ipv6 mismatch warning bug
from scapy.all import sr1, IPv46, TCP

# The top 20 ports from the nmap website
TOP_20_PORTS=[80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 5000, 1723, 111, 995, 993, 5900, 631, 161, 137, 123, 138, 1434, 445, 135, 67, 139, 500, 68, 520, 1900, 4500, 514, 49152, 162, 69]

class PortScanner:

    '''
    The PortScanner object is used to scan a host for open ports.

    On systems except windows it will send TCP SYN packets to a host and waits for a SYN + ACK response which indicates that the port is open.
    If the system is windows then it will use the Scapy API, this requires WinPcap to be installed.

    Attributes:
        progress (float): Returns the scan progress in %.
        _threads (list[threading.Thread]): Contains all the threads running.
        _results (dict): Stores all the open ports found during the scan.
        _event (threading.Event): Used to stop running threads.
        _progress (int): Tracks how many ports have been scanned.
        _retries (int): How many times to retry a port scan.
    '''

    def __init__(self, target: str, ports: str=None) -> None:
        
        '''
        The init method takes the target and ports (seperated by ,) to scan.

        If no ports are passed the top 20 ports from the nmap website will be used.
        Passing "-" as the port will make it scan all ports 1 - 65535.
        '''

        self._threads = []
        self._results = {}
        self._event = threading.Event()
        self._progress = 0
        self._retries = 0

        if valid_target := network.helpers.is_valid_host(target):
            self.target = valid_target
        else:
            logger.log(f'Invalid target "{target}"', level=logger.Level.ERROR)

        if not ports:
            self.ports = TOP_20_PORTS

        elif ports == '-':

            # Adds the most common ports to the front of the scanning queue.
            self.ports = TOP_20_PORTS
            self.ports.extend(list(range(1, 65536)))

        else:
            self.ports = [int(x) for x in ports.split(',')]

        if hasattr(self, 'target'):

            self.src = network.helpers.default_interface(self.target)
            self.src_port = random.randint(1, 65536)

        self._queue = helpers.QueueHandler(self.ports)

        # Checks if all the required variables are ready.
        self.ready = bool(
            hasattr(self, 'target') and
            hasattr(self, 'src')
        )

    @property
    def progress(self) -> int:
        '''
        Calculates the scan progress in percentage and returns it.
        '''
        return round((self._progress / self._queue._queue.maxsize) * 100, 2)

    def _syn_scan(self):

        '''
        Iterates each port in the self._ports list and sends a TCP SYN packet.

        Each response will be checked for a SYN + ACK packet to indicate that the port is open.
        If the os.platform is detected as windows it will use the Scapy API to send the packets, this requires WinPcap to be installed.
        '''

        for port in self._queue:

            if self._event.is_set():
                break

            # Skip the port if it has already been scanned
            if port in self._results:
                continue

            for retry in range(self._retries):

                # Uses Scapy API if the platform is windows
                if sys.platform == 'win32':
                    
                    ip_header = IPv46(dst=str(self.target))
                    syn = TCP(sport=self.src_port, dport=port, flags='S')

                    if (packet := sr1(ip_header / syn, timeout=(self.timeout / 1000) * (retry + 1), verbose=0)) != None \
                    and packet.haslayer(TCP) and packet[TCP].flags == network.Flags.SYN | network.Flags.ACK and port not in self._results:

                        logger.log(f'Port {port} is open', level=logger.Level.LOG)
                        self._results[port] = {'state': 'open', 'service': 'unknown'}

                        break

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
                    tcp.flags = network.Flags.SYN
                    tcp.window = 5840

                    packet = ip.pack() + tcp.pack()

                    try:
                        self.s.sendto(packet, (str(self.target), 0))
                        break
                    except Exception as e:
                        logger.log(f'Failed to send SYN packet {e}', level=logger.Level.ERROR)
                        time.sleep(self.timeout / 1000)

            self._progress += 1

    def _listener(self):

        '''
        Listens for incoming TCP packets from the host that is being scanned.

        This function should not be called on windows systems as raw TCP sockets is not supported.
        '''
        
        while not self._event.is_set():

            # Use select to prevent s.recvfrom() from infinite blocking if nothing is being received.
            read, write, error = select.select([self.s], [], [], 0.5)
            
            if not read:
                continue

            data, addr = self.s.recvfrom(1024)

            ip = network.models.IPHeader(data[0:20])
            tcp = network.models.TcpHeader(data[20:40])

            # Skip if the SYN+ACK response was already received for this port
            if tcp.src_port in self._results:
                continue

            # Filter out unwanted traffic
            if ip.src != self.target or tcp.dst_port != self.src_port:
                continue

            # Filter out packets with RST flag set.
            if tcp.is_flags_set(network.Flags.RST):
                continue

            # Check if the packet has ACK + SYN flags set.
            if tcp.is_flags_set(network.Flags.ACK | network.Flags.SYN):

                port = int(tcp.src_port)

                logger.log(f'Port {port} is open', level=logger.Level.INFO)
                self._results[port] = {'state': 'open', 'service': 'unknown  '}

    def stop(self):
        '''
        Stops the current scan.

        Sets the threading.Event() to make every thread exit.
        '''
        self._event.set()

    def _worker(self):

        '''
        The main method that spawns the scanner threads and stopping.

        Sets the timeout to the average round-trip-time + 100ms and sets the timeout to the result.

        '''

        logger.log('Calculating Average RTT...', level=logger.Level.INFO)

        try:
            self.timeout = network.helpers.avg_rtt(self.target) + 100
        except PermissionError:
            logger.log('Permission error while creating socket', level=logger.Level.ERROR)

        # Rounds the round-trip-time to 2 decimal places for prettier output.
        rtt = round(self.timeout - 100, 2)

        logger.log(f'Average RTT: {rtt} ms', level=logger.Level.INFO)

        # 25 Threads is created if the platform is windows.
        # 1 Thread is created if not windows.
        # This is done because windows blocks raw TCP sockets so it uses to scapy with threading instead.
        for _ in range(25 if sys.platform == 'win32' else 1):

            thread = threading.Thread(target=self._syn_scan)
            thread.daemon = True
            thread.start()
            
            self._threads.append(thread)

        while not self._event.is_set():

            try:

                # Exit if there are no ports left to scan.
                if self._queue.length == 0:
                    self._event.set()

                time.sleep(1 / 1000)

            except KeyboardInterrupt:
                self._event.set()
                logger.log('Stopping threads...', level=logger.Level.INFO)

        try:

            for thread in self._threads:

                thread.join()
            self._threads.remove(thread)

        except KeyboardInterrupt:
            pass

        return self._results

    def scan(self, retries : int=3, background : bool=False):

        '''
        Starts a new port scan.

        If the platform is not windows it will create a raw TCP socket and start a new thread on the _listener method.

        Args:
            retries (int): How many times to retry a port check (3 by default).
            background (bool): Starts the scan in the background if True (False by default).

        Returns:
            list: The list of ports found.
            bool: If background is True, it will return True if the background process starts successfully.
        '''

        self._retries = retries
        
        self._event.clear()

        if sys.platform != 'win32':

            # Sets the socket family to IPv4 or IPv6 based on the target address.
            family = socket.AF_INET if self.target.version == 4 else socket.AF_INET6
            
            self.s = socket.socket(family, socket.SOCK_RAW, socket.IPPROTO_TCP)
            self.s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self.s.bind(('0.0.0.0', 0))

            self.listener_thread = threading.Thread(target=self._listener)
            self.listener_thread.daemon = True
            self.listener_thread.start()

        if background:

            self.background_thread = threading.Thread(target=self._worker)
            self.background_thread.daemon = True
            self.background_thread.start()

            return True
        
        else:
            return self._worker()
