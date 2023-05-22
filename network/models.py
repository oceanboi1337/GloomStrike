import struct, ipaddress, enum

class Flags(enum.IntEnum):
	FIN = 0x1
	SYN = 0x2
	RST = 0x4
	PSH = 0x8
	ACK = 0x10

class IPHeader:

	def __init__(self, data : bytes) -> None:

		self.data = data[0:20]
		self.fields = struct.unpack('!BBHHHBBH4s4s', self.data)
		
		self._version = self.fields[0]
		self._tos = self.fields[1]
		self._length = self.fields[2]
		self._identifier = self.fields[3]
		self._flags = self.fields[4]
		self._ttl = self.fields[5]
		self._protocol = self.fields[6]
		self._checksum = self.fields[7]
		self._src = self.fields[8]
		self._dst = self.fields[9]

	@property
	def src(self):
		return ipaddress.ip_address(self._src)
	
	@property
	def dst(self):
		return ipaddress.ip_address(self.dst)

class TcpHeader:

		def __init__(self, data : bytes) -> None:
			 
			self.data = data
			self.fields = struct.unpack('!HHLLBBHHH', self.data)
			
			self._src_port = self.fields[0]
			self._dst_port = self.fields[1]
			self._sequence = self.fields[2]
			self._ack = self.fields[3]
			self._offset = self.fields[4]
			self._flags = self.fields[5]
			self._window = self.fields[6]
			self._checksum = self.fields[7]
			self._pointer = self.fields[8]
		
		@property
		def src_port(self):
			return self._src_port
		
		@property
		def dst_port(self):
			return self._dst_port
		
		def is_flags_set(self, flags : int):
			return self._flags & flags == self._flags