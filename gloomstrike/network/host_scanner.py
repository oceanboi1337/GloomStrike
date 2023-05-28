import socket, threading, select, time, os
import gloomstrike.network as network
from gloomstrike import logger, helpers

from scapy.all import srp, Ether, ARP

class HostScanner:

    def __init__(self, target : str, logger : logger.Logger=None) -> None:

        self._threads = []
        self._results = {}
        self._progress = 0
        self._logger = logger
        self._event = threading.Event()

        self._target = network.helpers.is_valid_network(target)

        if not self._target:
            self._logger.error(f'Invalid target {target}')

        else:

            self._logger.info('Generating host list')
            self._hosts = helpers.QueueHandler([host for host in self._target.hosts()])

        try:

            self.s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            self.s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        except Exception as e:
            self._logger.error('Failed to setup socket: {e}')

        self.ready = bool(
            self._target and
            hasattr(self, 's')
        )

    def _fetch_details(self):

        for host, details in self.nslookup_list:

            if self._event.is_set():
                break

            ip = network.helpers.is_valid_host(host)

            if mac := details.get('mac'):

                if manufacturer := network.helpers.device_lookup(mac):

                    self._logger.info(f'Found manufacturer {host} -> {manufacturer}')
                    self._results[host]['device'] = manufacturer

            if hostname := network.helpers.nslookup(ip, reverse=True):

                self._logger.info(f'Found hostname {host} -> {hostname}')
                self._results[host]['hostname'] = hostname

            else:
                self._logger.error(f'Reverse nslookup failed for {host}')

    def _gather_details(self):

        thread_amount = int(len(self._results) / 100) * 5 # Use threads equal to 5% of hosts found

        for tid in range(thread_amount + 1):

            thread = threading.Thread(target=self._fetch_details)
            thread.daemon = True
            thread.start()

            self._threads.append(thread)

        start = time.time()

        while time.time() - start < 5:

            try:

                if hasattr(self, 'icmp_receiver_thread') and not self.icmp_receiver_thread.is_alive():

                    self._event.set()
                    self.icmp_receiver_thread.join()

                time.sleep(1 / 1000)

            except KeyboardInterrupt:
                break

        self._event.set()

    def _icmp_receiver(self):

        while not self._event.is_set():

            read, write, error = select.select([self.s], [], [], 0)

            if read:

                data, addr = self.s.recvfrom(1024)

                header = network.models.IPHeader(data[0:20])

                if header.src not in self._results:

                    details = {
                        'hostname': str(header.src),
                        'version': header.src.version,
                    }

                    self._results[str(header.src)] = details

            time.sleep(1 / 1000)

    def _icmp_discover(self):

        self.icmp_receiver_thread = threading.Thread(target=self._icmp_receiver)
        self.icmp_receiver_thread.daemon = True
        self.icmp_receiver_thread.start()

        src = network.helpers.default_interface()

        for host in self._target:

            if host == self._target.broadcast_address:
                continue

            if self._event.is_set():
                break

            for retry in range(self.retries):

                if self._event.is_set():
                    break

                ip = network.models.IPHeader()
                ip.version = 4
                ip.length = 0x28
                ip.protocol = socket.IPPROTO_ICMP
                ip.ttl = 255
                ip.identifier = os.getpid() & 0xffff
                ip._src = src
                ip._dst = host.packed

                icmp = network.models.IcmpHeader()
                icmp.type = 8
                icmp.code = 0
                icmp.id = os.getpid() & 0xffff

                try:

                    self.s.sendto(ip.pack() + icmp.pack(), (str(host), 0))
                    self._progress += 1

                except Exception as e:
                    self._logger.error(f'Error while sending packet to {host} {e}')

                try:
                    time.sleep(1 / 1000)
                except KeyboardInterrupt:
                    self._event.set()
                    return

        self.nslookup_list = helpers.QueueHandler([x for x in self._results.items()])

        self._gather_details()

    def _arp_discover(self):

        self._logger.info(f'Sending ARP packets...')    
        
        eth = Ether(dst='ff:ff:ff:ff:ff:ff')
        arp = ARP(pdst=[str(host) for host in self._hosts])

        answers, unanswered = srp(eth / arp, timeout=3, verbose=0, promisc=False)

        self._logger.info(f'Processing {len(answers)} answers')

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

        self.nslookup_list = helpers.QueueHandler([x for x in self._results.items()])

        return self._gather_details()

    def start(self, protocol : network.Protocol, retries : int=3, background : bool=False):

        self.retries = retries

        worker : callable = None

        match(protocol):

            case network.Protocol.ARP:
                worker = self._arp_discover
            case network.Protocol.ICMP:
                worker = self._icmp_discover

        if not worker:
            self._logger.error(f'Invalid protocol detected')
            return
        
        if background:

            self.background_thread = threading.Thread(target=worker)
            self.background_thread.daemon = True
            self.background_thread.start()

            return self.background_thread.is_alive()

        else:

            return worker()