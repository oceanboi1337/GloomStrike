import socket, threading, select, time, os
import gloomstrike.network as network
from gloomstrike import logger, helpers

from scapy.all import srp, Ether, ARP

class HostScanner:

    '''
    The HostScanner class allows for scanning of a network using a CIDR as the target.

    It supports ARP and ICMP scanning to discover hosts on a network.
    The ICMP method uses raw sockets to send ICMP requests while running a ICMP receiver in a background thread.
    Using raw sockets requires escalated privileges (Administrator / Root).
    The ARP method uses Scapy's API to send ARP packets to discover hosts, this requires WinPcap to be installed if used on windows.

    Attributes:
        _threads (list[threading.Thread]): A list of the running threads.
        _results (dict): Dictionary that contains the results of a network scan.
        _event (threading.Event): Even that can be .set() to stop the threads.
        _target (ipaddress.IPv4Network | ipaddress.IPv6Network) Is the network object which generates the address for each host.
        _hosts (ipaddress.IPv4Address | ipaddress.IPv6Address) A list of IP Addresses that will be used in the scan.
        _s (socket.socket) Is the raw socket used by the ICMP scanner.
        _icmp_receiver_thread (threading.Thread) Is the thread that receives ICMP responses.
        _background_thread (threading.Thread) Is the background thread used to run scans without blocking execution of the program.

    Methods:
        start(protocol: network.Protocol, retries: int = 3, background: bool = False): Starts the network scan.

    '''

    def __init__(self, target : str) -> None:

        '''
        Checks if the target CIDR is valid and generates a list of hosts from it.

        The __init__ method sets up a raw socket that is used to send ICMP RAW packets, it requires Administrator / Root privileges.

        Args:
            target (str): The target CIDR to scan, 192.168.1.0/24.
        '''

        self._threads = []
        self._results = {}
        self._progress = 0
        self._event = threading.Event()

        self._target = network.helpers.is_valid_network(target)

        if not self._target:
            logger.log(f'Invalid target {target}', level=logger.Level.ERROR)

        else:

            logger.log('Generating host list', level=logger.Level.INFO)
            self._hosts = helpers.QueueHandler([host for host in self._target.hosts()])

        try:

            self._s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

            # This socket option is enabled to manually craft the IP header.
            self._s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        except Exception as e:
            logger.log('Failed to setup socket: {e}', level=logger.Level.ERROR)

        # Makes sure all the required variables are set.
        self.ready = bool(
            self._target and
            hasattr(self, 's')
        )

    def _fetch_details(self):

        '''
        Iterates through the list of hosts found to gather more details about them.

        The details are: MAC address and manufacturer (ARP scan only) and hostname.
        These will be added to the self._results dict.
        '''

        for host, details in self.nslookup_list:

            if self._event.is_set():
                break

            ip = network.helpers.is_valid_host(host)

            if mac := details.get('mac'):

                if manufacturer := network.helpers.device_lookup(mac):

                    logger.log(f'Found manufacturer {host} -> {manufacturer}', level=logger.Level.INFO)
                    self._results[host]['device'] = manufacturer

            if hostname := network.helpers.nslookup(ip, reverse=True):

                logger.log(f'Found hostname {host} -> {hostname}', level=logger.Level.INFO)
                self._results[host]['hostname'] = hostname

            else:
                logger.log(f'Reverse nslookup failed for {host}', level=logger.Level.WARNING)

    def _gather_details(self):

        # Use threads equal to 5% of hosts found
        thread_amount = int(len(self._results) / 100) * 5

        for tid in range(thread_amount + 1):

            thread = threading.Thread(target=self._fetch_details)
            thread.daemon = True
            thread.start()

            self._threads.append(thread)

        start = time.time()

        # Only receive ICMP responses for 5 seconds.
        while time.time() - start < 5:

            try:

                if hasattr(self, '_icmp_receiver_thread') and not self._icmp_receiver_thread.is_alive():

                    self._event.set()
                    self._icmp_receiver_thread.join()

                # Sleep for 1ms to prevent CPU hog.
                time.sleep(1 / 1000)

            except KeyboardInterrupt:
                break

        self._event.set()

    def _icmp_receiver(self):

        '''
        Method that is run in a background thread to receive ICMP packets.

        select() is used in a while loop to check when a packet has been received, this is to allow for the KeyboardInterrupt exception.

        '''

        while not self._event.is_set():

            read, write, error = select.select([self._s], [], [], 0)

            if read:

                data, addr = self._s.recvfrom(1024)

                # Pass the first 20 bytes (IP Header) of the packet to the IPHeader class to be parsed.
                header = network.models.IPHeader(data[0:20])

                # Ignore the packet if its already in results.
                if header.src not in self._results:

                    details = {
                        'hostname': str(header.src),
                        'version': header.src.version, # IP Version
                    }

                    self._results[str(header.src)] = details # Add the host to the self._results dict.

            time.sleep(1 / 1000)

    def _icmp_discover(self):

        '''
        Sends ICMP packets to every host in the CIDR range.

        Before sending packets it will spawn the _icmp_receiver_thread to receive responses.

        Calls the _gather_details() function after sending all the packets.
        '''

        self._icmp_receiver_thread = threading.Thread(target=self._icmp_receiver)
        self._icmp_receiver_thread.daemon = True
        self._icmp_receiver_thread.start()

        src = network.helpers.default_interface()

        for host in self._target:

            # Filter out broadcast address.
            if host == self._target.broadcast_address:
                continue

            if self._event.is_set():
                break

            for retry in range(self.retries):

                if self._event.is_set():
                    break

                # Custom IPHeader class used to easily create and parse packets.
                ip = network.models.IPHeader()
                ip.version = 4
                ip.length = 0x28
                ip.protocol = socket.IPPROTO_ICMP
                ip.ttl = 255
                ip.identifier = os.getpid() & 0xffff
                ip._src = src.packed
                ip._dst = host.packed

                # Custom ICMP header class used to create and parse packets.
                icmp = network.models.IcmpHeader()
                icmp.type = 8
                icmp.code = 0
                icmp.id = os.getpid() & 0xffff

                try:

                    # Combines the IP/ICMP headers into a packet and sends it.
                    self._s.sendto(ip.pack() + icmp.pack(), (str(host), 0))
                    self._progress += 1

                except Exception as e:
                    logger.log(f'Error while sending packet to {host} {e}', level=logger.Level.ERROR)

                try:
                    time.sleep(1 / 1000)
                except KeyboardInterrupt:
                    self._event.set()
                    return

        # Hosts to find hostname for.
        self.nslookup_list = helpers.QueueHandler([x for x in self._results.items()])

        self._gather_details()

    def _arp_discover(self):

        '''
        Sends ARP packets to every host in the CIDR.

        Uses Scapy's API to send ARP packets and receive responses.
        '''

        logger.log(f'Sending ARP packets...', level=logger.Level.INFO)
        
        eth = Ether(dst='ff:ff:ff:ff:ff:ff')
        arp = ARP(pdst=[str(host) for host in self._hosts]) # Sets the destination to all the hosts in the CIDR range.

        answers, unanswered = srp(eth / arp, timeout=3, verbose=0, promisc=False)

        logger.log(f'Processing {len(answers)} answers', level=logger.Level.INFO)

        # Iterate of the answers and unpack the send and recv data.
        for send, recv in answers:

            mac = recv.hwsrc
            src = network.helpers.is_valid_host(recv.psrc)

            details = {
                'mac': mac,
                'device': None,
                'hostname': str(src),
                'version': src.version,
            }

            self._results[str(src)] = details

        # Add hosts to the list to gather more details about them.
        self.nslookup_list = helpers.QueueHandler([x for x in self._results.items()])

        return self._gather_details()

    def start(self, protocol : network.Protocol, retries : int=3, background : bool=False):

        '''
        Starts the host scan and spawns the threads.

        Checks which protocol will be used and spawns the appropriate thread.

        Args:
            protocol (network.Protocol): Which protocol to use, ICMP or ARP.
            retries (int): How many times to retry sending a packet.
            background (bool): Weather or not to run the scan in the background or not.

        Returns:
            dict: The results of the scan.
        '''

        self.retries = retries

        # Variable to store the reference to the method.
        worker : callable = None

        match(protocol):

            case network.Protocol.ARP:
                worker = self._arp_discover # Sets the worker callable to _arp_discover.
            case network.Protocol.ICMP:
                worker = self._icmp_discover# Sets the worker callable to _icmp_discover.

        if not worker:
            logger.log(f'Invalid protocol detected', level=logger.Level.ERROR)
            return
        
        if background:

            # Starts the background thread if True.
            self.background_thread = threading.Thread(target=worker)
            self.background_thread.daemon = True
            self.background_thread.start()

            return self.background_thread.is_alive()

        else:

            # Starts the scan in blocking mode and return the results.
            return worker()