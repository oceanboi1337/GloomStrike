import socket, threading, select, ipaddress, time, sys, network, helpers

from scapy.all import srp, Ether, ARP

class HostScanner:

    def __init__(self, db : str=None) -> None:

        self.threads = []
        self.results = {}

        self.s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    def _fetch_details(self):

        for host, details in self.nslookup_list:

            ip = ipaddress.ip_address(host)

            if mac := details.get('mac'):

                self.results[host]['device'] = network.helpers.device_lookup(mac)

            hostname = network.helpers.nslookup(ip, reverse=True)
            self.results[host]['hostname'] = hostname

    def _icmp_discover(self):

        thread = threading.Thread(target=self._icmp_receiver)
        thread.start()

        for host in self.target:

            src = network.helpers.default_interface()

            packet = network.helpers.create_packet_icmp(str(src), str(host))

    def _arp_discover(self):

        print(f'[INFO]: Sending ARP packets...')    
        
        eth = Ether(dst='ff:ff:ff:ff:ff:ff')
        arp = ARP(pdst=[str(host) for host in self.hosts])

        answers, unanswered = srp(eth / arp, timeout=3, verbose=0, promisc=False)

        print(f'[INFO]: Processing {len(answers)} answers')

        for send, recv in answers:

            mac = recv.hwsrc
            src = network.helpers.is_valid_host(recv.psrc)

            details = {
                'mac': mac,
                'device': None,
                'hostname': str(src),
                'version': src.version,
            }

            self.results[str(src)] = details

        self.nslookup_list = helpers.QueueHandler([x for x in self.results.items()])

        thread_amount = int(len(self.results) / 100) * 5 # Use threads equal to 5% of hosts found

        for tid in range(thread_amount + 1):

            thread = threading.Thread(target=self._fetch_details)
            thread.daemon = True
            thread.start()

            self.threads.append(thread)

        for thread in self.threads:
            thread.join()

    def start(self, cidr : str, protocol : network.Protocol, background : bool=False):

        self.target = network.helpers.is_valid_network(cidr)

        if not self.target:
            print(f'[ERROR]: Invalid CIDR {cidr}')
        
        print(f'[INFO]: Generating host list')
        self.hosts = helpers.QueueHandler([host for host in self.target.hosts()])

        worker : callable = None

        match(protocol):

            case network.Protocol.ARP:
                worker = self._arp_discover
            case network.Protocol.ICMP:
                worker = self._icmp_discover

        if not worker:
            print(f'[ERROR]: Invalid protocol detected')
            return
        
        if background:

            self.background_thread = threading.Thread(target=worker)
            self.background_thread.daemon = True
            self.background_thread.start()

            return self.background_thread.is_alive()

        else:

            return worker()