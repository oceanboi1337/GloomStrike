import ipaddress, threading, network, socket, sys, select, time, random
import helpers
from collections import defaultdict

if sys.platform == 'win32':
	from scapy.all import sr1, IP, TCP

class PortScanner:

	def __init__(self, target : str, ports : str, src_port : int=None) -> None:
		
		self.threads = []
		self.results = {}
		self.event = threading.Event()

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

	def _syn_scan(self):

		packets_sent = 0

		for port in self.queue:

			if sys.platform == 'win32':

				answers = sr1(IP(), verbose=0)

			else:

				if port in self.results:
					continue

				packet = network.helpers.create_packet_syn(self.src, self.target, self.src_port, port)

				try:

					self.s.sendto(packet, (str(self.target), 0))
					packets_sent += 1

				except Exception as e:
					
					print(f'[ERROR]: Failed to send SYN packet', e)

		return packets_sent

	def _listener(self):

		while not self.event.is_set():

			read, write, error = select.select([self.s], [], [], 0)

			if read:

				data, addr = self.s.recvfrom(1024)

				ip = network.models.IPHeader(data[0:20])
				tcp = network.models.TcpHeader(data[20:40])

				if ip.src != self.target or tcp.dst_port != self.src_port:
					continue

				if tcp.is_flags_set(network.Flags.RST):
					continue

				if tcp.is_flags_set(network.Flags.ACK | network.Flags.SYN):

					port = int(tcp.src_port)
					service = 'unknown'

					print(f'[INFO]: Port {port} is open')

					if port not in self.results:

						self.results[port] = {'state': 'open', 'service': service}

	def stop(self):
		self.event.set()

	def worker(self, timeout : int=3, retries : int=3):

		for retry in range(retries):

			packets_sent = self._syn_scan()
			if packets_sent == 0:
				continue

			time.sleep(timeout)
			self.queue.reset()

			print(f'[INFO]: Attempt {retry}')

		self.event.set()

		return self.results

	def scan(self, timeout : int=3, retries : int=3, background : bool=False):

		if sys.platform != 'win32':

			family = socket.AF_INET if self.target.version == 4 else socket.AF_INET6
			
			self.s = socket.socket(family, socket.SOCK_RAW, socket.IPPROTO_TCP)
			self.s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

			self.listener_thread = threading.Thread(target=self._listener)
			self.listener_thread.daemon = True
			self.listener_thread.start()

		if background:

			self.background_thread = threading.Thread(target=self.worker, args=[timeout, retries])
			self.background_thread.daemon = True
			self.background_thread.start()

			return self.results
		
		else:
			return self.worker(timeout, retries)