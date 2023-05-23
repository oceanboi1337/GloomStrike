import socket, threading, select, ipaddress, time, sys, network, helpers

from scapy.all import srp, Ether, ARP

class NetworkMapper:

    def __init__(self, db : str=None) -> None:

        self.threads = []
        self.results = []

        self.s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    def _icmp_discover(self):

        thread = threading.Thread(target=self._icmp_receiver)
        thread.start()

        for host in self.target:

            src = network.helpers.default_interface()

            packet = network.helpers.create_packet_icmp(str(src), str(host))

    def _arp_discover(self):

        print(f'[INFO]: Sending ARP packets...')
        
        eth = Ether(dst='ff:ff:ff:ff:ff:ff')
        arp = ARP(pdst=self.target.items)

        answers, unanswered = srp(eth / arp, timeout=3, verbose=0, promisc=False)

        print(f'[INFO]: Processing {len(answers)} answers')

        for send, recv in answers:

            mac = recv.hwsrc
            src = network.helpers.is_valid_host(recv.psrc)
            hostname = network.helpers.nslookup(src, reverse=True)

            details = {
                'mac': mac,
                'hostname': hostname,
                'version': src.version
            }

            self.results[str(src)] = details

    def discover(self, cidr : str, protocol : network.Protocol):

        if (target := network.helpers.is_valid_network(cidr)) == None:

            print(f'[ERROR]: Invalid CIDR {cidr}')
            return
        
        self.target = helpers.QueueHandler([host for host in target.hosts()])
        
        if protocol == network.Protocol.ARP:
            return self._arp_discover()