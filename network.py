import socket, struct, os, threading, random, select, ipaddress, time

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
    
    def icmp_receiver(self, s : socket.socket, event : threading.Event):

        counter = 0

        while 1:

            if event.is_set():
                break

            r, w, e = select.select([s], [], [], 0.01)

            if r:

                data, addr = s.recvfrom(1024)

                try:
                    hostname = socket.gethostbyaddr(addr[0])
                    self.results[addr] = {'hostname': hostname, 'reply': True}
                except Exception as e:
                    if self.verbose > 0:
                        print(e)

    def discover(self, cidr : str):

        network = None

        try:
            network = ipaddress.IPv4Network(cidr)
        except ValueError as e:
            print(f'[ERROR]: Invalid CIDR ({cidr}): {e}')

        if not network:
            return

        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

        event = threading.Event()

        thread = threading.Thread(target=self.icmp_receiver, args=[s, event])
        thread.start()

        for host in network.hosts():

            try:
                s.sendto(self.create_icmp_packet(), (str(host), 0))
            except Exception as e:
                print('Error:', e, host)

        #event.set()
        #thread.join()

        print('Done Sending')
        try:
            while not event.is_set():
                time.sleep(0.1)
        except KeyboardInterrupt as e:
            event.set()
            thread.join()

        print(self.results)

network = NetworkMapper()
network.discover(cidr='192.168.1.0/24')