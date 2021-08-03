#!/usr/bin/env python3
# Goodix SPI Protocol Parser

from __future__ import annotations
import abc, sys, math, struct

def indent(s): return '\n\t'.join(s.split('\n'))
def hexdump(x): return ' '.join(f"{i:02x}" for i in x) or "b''"

class Flags:
	MSG_PROTOCOL = 0xa0

class Repr:
	@staticmethod
	def repr(x):
		if (isinstance(x, int)): return f"{x:#04x}\033[0m  \033[3;90m# {x:d} / 0b{int(bin(x)[2:]):08d}\033[0m"
		elif (isinstance(x, bytes)): return hexdump(x)
		else: return str(x)

class Validatable(abc.ABC):
	@abc.abstractmethod
	def validate(self): ...

class ChecksumValidatable(Validatable):
	@abc.abstractmethod
	def validate(self, *, checksum=None, **kwargs):
		super().validate(**kwargs)
		assert (checksum is None or checksum == self.checksum)

class Packable(Validatable, Repr):
	fmt: str
	fields: tuple

	def __str__(self):
		ml = max(map(len, self.all_fields), default=0)
		_args = self._args
		args = (' \033[2m(\033[0;95m'+f"\033[0;2m,\033[0m \033[95m".join(_args)+'\033[0;2m)\033[0m' if (_args) else '')
		return f"\033[1;94m{self.__class__.__name__}\033[0m{args}"+' {\n\t'+('\n\t'.join(f"\033[93m{i}\033[0m{' '*(ml-len(i))} = \033[96m{indent(self.repr(getattr(self, i)))}\033[0m" for i in self.all_fields if not i.startswith('_')) or '\033[3;90m# empty\033[0m')+'\n}'+f"  \033[2;3;90m# {hexdump(self.pack())}\033[0m"

	@property
	def _args(self):
		return ()

	def pack(self, *, fields=None, validate=True) -> bytes:
		if (fields is None): fields = self.all_fields
		if (validate): self.validate()
		return struct.pack('<'+self.fmt, *(getattr(self, i) for i in fields))

	@property
	def all_fields(self):
		return (*self.fields, *getattr(super(), 'all_fields', ()))

	@classmethod
	def unpack(cls, data: bytes) -> (Packable, bytes):
		fmt = '<'+cls.fmt
		return (cls(*struct.unpack_from(fmt, data)), data[struct.calcsize(fmt):])

class RTRMessage(Packable):
	fmt = 'BBBB'
	fields = ('_bb', '_f1', '_00', '_00')

	def __init__(self, _bb=0xbb, _f1=0xf1, _00_1=0x00, _00_2=0x00, **kwargs):
		self._bb, self._f1, self._00, self._00 = _bb, _f1, _00_1, _00_2
		super().__init__(**kwargs)

	def validate(self, **kwargs):
		super().validate(**kwargs)

	@property(lambda _: 0xbb).setter
	def _bb(self, x):
		assert (x == 0xbb)

	@property(lambda _: 0xf1).setter
	def _f1(self, x):
		assert (x == 0xf1)

	@property(lambda _: 0x00).setter
	def _00(self, x):
		assert (x == 0x00)

class Header(Packable, ChecksumValidatable):
	__slots__ = ()

	@property
	def _args(self):
		return (repr(self.fmt),)

class SPIHeader(Header):
	__slots__ = ('seq',)

	fmt = 'BBH'
	fields = ('_cc', '_f2', *__slots__)

	def __init__(self, _cc=0xcc, _f2=0xf2, seq: int = None, **kwargs):
		assert (seq is not None)
		self._cc, self._f2, self.seq = _cc, _f2, seq
		super().__init__(**kwargs)

	def validate(self, **kwargs):
		super().validate(**kwargs)
		assert all((
			0 <= self.seq <= 0xffff,
		))

	@property(lambda _: 0xcc).setter
	def _cc(self, x):
		assert (x == 0xcc)

	@property(lambda _: 0xf2).setter
	def _f2(self, x):
		assert (x == 0xf2)

class PackHeader(Header):
	__slots__ = ('flags', 'length')

	fmt = 'BHB'
	fields = (*__slots__, 'checksum')

	def __init__(self, flags: int, length: int, checksum: int = None):
		super().__init__()
		self.flags, self.length = int(flags), int(length)
		self.validate(checksum=checksum)

	def validate(self, *, checksum=None, **kwargs):
		super().validate(checksum=checksum, **kwargs)
		assert all((
			0 <= self.flags <= 0xff,
			0 <= self.length <= 0xffff,
		))

	@property
	def checksum(self):
		return (sum(struct.pack('<BH', self.flags, self.length)) % 0x100)


class Package(Packable, Validatable, abc.ABC):
	__slots__ = ()

	@abc.abstractmethod
	def pack(self, *, fields=None, validate=True): ...

	@abc.abstractclassmethod
	def unpack(cls, data): ...

	@property
	def fields(self):
		return self.__slots__

class ProtocolPackage(Package):
	__slots__ = ('flags', 'payload')

	def __init__(self, flags: int, payload: Payload):
		super().__init__()
		self.flags, self.payload = int(flags), payload
		self.validate()

	def validate(self, **kwargs):
		super().validate(**kwargs)
		assert all((
			0 <= self.flags <= 0xff,
		))

	def pack(self, *, validate=True):
		if (validate): self.validate()
		payload = self.payload.pack()
		header = PackHeader(
			flags = self.flags,
			length = len(payload),
		)
		return (header.pack() + payload)

	@classmethod
	def unpack(cls, data):
		header, data = PackHeader.unpack(data)
		assert (len(data) >= header.length)
		payload, leftover = Packet.unpack(data)
		return (cls(flags=header.flags, payload=payload), leftover)

class SPIPackage(Package):
	__slots__ = ('seq', 'data')

	def __init__(self, seq: int, data: Package):
		super().__init__()
		self.seq, self.data = int(seq), data
		self.validate()

	def validate(self, **kwargs):
		super().validate(**kwargs)
		assert all((
			0 <= self.seq <= 0xffff,
		))

	def pack(self, *, validate=True):
		if (validate): self.validate()
		data = self.data.pack()
		header = SPIHeader(
			seq = self.seq,
		)
		return (header.pack() + data)

	@classmethod
	def unpack(cls, data):
		header, data = SPIHeader.unpack(data)
		package, leftover = ProtocolPackage.unpack(data)
		return (cls(seq=header.seq, data=package), leftover)


class _PacketPayloadMeta(abc.ABCMeta):
	def __new__(metacls, name, bases, classdict):
		_fields = classdict.get('fields', ())
		cls = super().__new__(metacls, name, bases, classdict)
		if (not isinstance(cls.pid, int)): return cls

		class Payload(Packable):
			__slots__ = tuple(i for i in _fields if i not in ('payload', 'leftover', 'checksum'))
			fmt = cls.fmt
			fields = ()

			def __init__(self, *args):
				for k, v in zip(self.__slots__, args):
					setattr(self, k, v)

			def pack(self):
				return super().pack(fields=self.__slots__)

			def validate(self):
				super().validate()

		cls.Payload = Payload
		cls.fields = sum((getattr(i, 'fields', ()) for i in bases), start=())
		return cls

class Packet(Packable, ChecksumValidatable, metaclass=_PacketPayloadMeta):
	__slots__ = ('payload', 'leftover')

	pid: int = abc.abstractproperty()
	fmt: str = ''
	fields: tuple = (*__slots__, 'checksum')

	def __init__(self, pid: int, payload, leftover: bytes = b'', checksum: int = None):
		self.payload, self.leftover = payload, leftover
		super().__init__()
		self.validate(pid=pid, checksum=checksum)

	@property
	def _args(self):
		return (f"{self.pid:#04x}", repr(self.fmt))

	def validate(self, *, pid=None, checksum=None, **kwargs):
		super().validate(checksum=checksum, **kwargs)
		assert all((
			0 <= self.pid <= 0xff,
			pid is None or pid == self.pid,
		))

	def pack(self, *, checksum=True):
		payload = bytearray(self.payload.pack() + self.leftover)
		if (checksum): payload.append(self.checksum)
		return struct.pack('<BH', self.pid, len(payload)+1) + payload

	@property
	def checksum(self):
		return ((0xaa - (sum(self.pack(checksum=False)) % 256)) % 256)

	@classmethod
	def unpack(cls, data):
		(pid, length), data = struct.unpack_from('<BH', data), data[struct.calcsize('<BH'):]
		if (cls is Packet):
			try: cls = next(i for i in cls.__subclasses__() if pid == getattr(i, 'pid', None))
			except StopIteration: raise ValueError(f"Packet with {pid=:#04x} is not implemented.")
		payload, data = data[:length-1], data[length-1:]
		checksum, data = struct.unpack_from('<B', data)[0], data[struct.calcsize('<B'):]
		return (cls(pid, cls.Payload(*struct.unpack_from('<'+cls.fmt, payload)), payload[struct.calcsize('<'+cls.fmt):], checksum), data)

class PacketNop(Packet):
	pid = 0x00
	fmt = 'I'
	fields = ('unknown',)

class PacketGetImage(Packet):
	pid = 0x20
	fmt = ''
	fields = ()

class PacketSwitchToFdtDown(Packet):
	pid = 0x32
	fmt = ''
	fields = ()

class PacketSwitchToFdtUp(Packet):
	pid = 0x34
	fmt = ''
	fields = ()

class PacketSwitchToFdtMode(Packet):
	pid = 0x36
	fmt = ''
	fields = ()

class PacketNav0(Packet):
	pid = 0x50
	fmt = ''
	fields = ()

class PacketQueryMcuState(Packet):
	pid = 0xae
	fmt = 'B'
	fields = ('unused_flags',)

class PacketAck(Packet):
	pid = 0xb0
	fmt = ''
	fields = ()


def decode_packet(data):
	res = list()

	for i in (RTRMessage, SPIPackage, SPIHeader, ProtocolPackage, PackHeader, Packet):
		try: r, data = i.unpack(data)
		except Exception as ex: r = ex
		res.append((i, r))
		if (not data): break

	return (res, data)

def decode_dump(hex, *, errors=True, last=0):
	if (hex and hex[0] in '<>'): dir, hex = hex[0], hex[1:]
	else: dir = None

	res, leftover = decode_packet(bytes.fromhex(hex))
	for t, r in res[-last:]:
		if (isinstance(r, Exception)):
			if (not errors): continue
			print(f"\033[91mError decoding \033[1m{t.__name__}\033[2m:\033[0;2m")
			sys.excepthook(r.__class__, r, r.__traceback__)
			print(end='\033[0m')
		else:
			if (dir is not None): print(f"\033[9{1+(dir=='>')}m{dir}\033[0m", end=' ')
			print(r)
		if (errors): print()
	if (leftover):
		if (dir is not None): print(f"\033[9{1+(dir=='>')}m{dir}\033[0m", end=' ')
		print(f"\033[1;2mLeftover\033[0m \033[1;90m(\033[0;2;95m{len(leftover)} bytes\033[0;1;90m)\033[0m \033[2m{{\033[0;2m\n\t"+'\n\t'.join(' '.join(f"{j:02x}" for j in leftover[i*8:(i+1)*8-4])+'  '+' '.join(f"{j:02x}" for j in leftover[i*8+4:(i+1)*8]) for i in range(math.ceil(len(leftover)/8)))+'\n\033[2m}\033[0m')
	print()


if (__name__ == '__main__'):
	for i in (
		'> cc f2 3b 82 a0 09 00 a9 ae 06 00 55 0e 52 00 00 41',
		'> bb f1 00 00',
		'< a0 18 00 b8 ae 15 00 02 02 31 00 00 00 01 00 90 63 00 00 00 00 00 00 00 00 19 19 8c',

		'> cc f2 3c 82 a0 14 00 b4 32 11 00 0c 01 80 ab 80 bc 80 a0 80 ae 80 a3 80 b0 f1 6c f5',
		'> bb f1 00 00',
		'< a0 06 00 a6 b0 03 00 32 01 c4',
		'> bb f1 00 00',
		'< a0 14 00 b4 32 11 00 02 00 3f 00 db 00 ee 00 bc 00 d8 00 bb 00 e1 00 2d',

		'> cc f2 3d 82 a0 06 00 a6 20 03 00 01 00 86',
		'> bb f1 00 00',
		'< a0 06 00 a6 b0 03 00 20 01 d6',
		'> bb f1 00 00',
		##	[
		'< b0 45 1e 13 17 03 03 1e 40 27 f3 32 11 58 74 c4 44 27 49 3d 03 6b 94 4a 35 9c 7a 0c 7e 37 5a 03 f2 25 5e c2 91 ae 14 44 9f 05 7c 1c 27 f0 be e9 13 98 71 4a b0 cc 06 34 16 7e 12 1e bb ed a3 96 09 57 cf 63 0a af 69 1b 38 8a 97 f0 21 27 a6 f4 03 6a da ba ae 54 17 42 d8 bc 0d 41 11 f3 6b 05 1f 13 0f b4 d2 a6 d0 6b df fc cd 3a 14 c7 fb fe d5 ad f4 9a ba c1 d4 d9 07 45 4d 54 a5 69 37 aa 2a d0 e6 87 74 59 2e 9c ae 91 76 d9 68 ed 58 f5 73 bc 74 07 99 6d 04 aa 32 b3 be 73 46 87 d0 02 c4 b1 57 7c 87 f8 cf d9 ac 0d ac c7 cc 71 1d 76 38 15 25 aa 7a 92 e5 4a 62 fa cd 4a af ba 46 77 c1 85 1b 47 9d 97 ad fc 0a 04 f1 d9 6e 36 54 19 9b 61 ed e8 b2 d9 6c 68 c5 32 d0 73 30 18 e8 9a ad 26 bc 1c eb 2f 8d f4 60 33 60 ea 34 37 e7 d4 84 16 79 d5 07 a3 6e 31 3a ab 6a 6f fd 9c e1 fa',
		'> bb f1 00 00',
		##	] ...32 times total, undecodeable, presumably all raw (with only a pack header, without oacket header) including this one.
		##	  Also, the `flags=b0' suggests that it's in TLS.

		'> cc f2 3e 82 a0 12 00 b2 34 0f 00 0e 01 80 88 80 92 80 79 80 87 80 78 80 8b 3b',
		'> bb f1 00 00',
		'< a0 06 00 a6 b0 03 00 34 01 c2',

		'> cc f2 3f 82 a0 12 00 b2 36 0f 00 0d 01 80 ab 80 bc 80 a0 80 ae 80 a3 80 b0 4f',
		'> bb f1 00 00',
		'< a0 06 00 a6 b0 03 00 36 01 c0',
		'> bb f1 00 00',
		'< a0 14 00 b4 36 11 00 00 01 3f 00 b8 00 da 00 a4 00 c3 00 ab 00 cb 00 b4',

		'> cc f2 40 82 a0 06 00 a6 20 03 00 01 00 86',
		'> bb f1 00 00',
		'< a0 06 00 a6 b0 03 00 20 01 d6',
		'> bb f1 00 00',
		##	[
		'< b0 45 1e 13 17 03 03 1e 40 10 23 a9 1f d8 2e 55 17 b1 5c 7c 0a 10 7d b9 7a f5 e3 55 98 6d f2 7c 8a 7c e2 d9 b0 69 40 aa 71 5b d4 f5 9c d4 d7 44 31 a5 7a ee bc 9b b1 44 44 ed 85 3d e0 fc ba 22 b7 b6 dc 7d 68 5a 06 50 35 26 d2 4a 89 9e 23 fb 57 ae e4 b7 23 f0 58 a2 a2 6a be 8a 71 2f 2e af 78 a3 66 09 62 9c bd b4 38 8d 1f cf 3d bf b9 10 06 c1 ab d7 98 c4 8b ac 1e 31 5a 6b 07 05 67 d3 0b 1f 38 1b e5 63 ba eb d1 9f 09 cf 81 61 25 92 9f fa b9 45 65 6f 98 d5 09 77 c3 86 02 0b e8 f0 5d bc d9 68 64 7d 90 81 9c 75 52 e2 75 fb 53 57 69 97 1b 2b 61 6c 3f 1d 91 cf 74 da f2 b6 92 4b d7 27 56 52 f9 3d 4d cb a5 f4 d7 88 cc 97 91 f4 65 be 7b b9 b7 d6 bb d4 5d 74 73 7c 5a e4 67 f9 65 a9 31 85 f4 09 74 1b 02 55 dc 34 41 75 4b ba fc 75 a0 5b 77 77 1c cb 94 f0 6a fb 8c f7 7f 50',
		'> bb f1 00 00',
		##	] ...32 times total, see above.

		'> cc f2 41 82 a0 12 00 b2 34 0f 00 0e 01 80 88 80 92 80 79 80 87 80 78 80 8b 3b',
		'> bb f1 00 00',
		'< a0 06 00 a6 b0 03 00 34 01 c2',

		'> cc f2 42 82 a0 12 00 b2 36 0f 00 0d 01 80 5c 80 6d 80 52 80 61 80 55 80 65 21',
		'> bb f1 00 00',
		'< a0 06 00 a6 b0 03 00 36 01 c0',
		'> bb f1 00 00',
		'< a0 14 00 b4 36 11 00 00 01 00 00 58 01 79 01 41 01 62 01 47 01 64 01 3d',

		'> cc f2 43 82 a0 14 00 b4 32 11 00 0c 01 80 ac 80 bc 80 a0 80 b1 80 a3 80 b2 a8 77 2d',
		'> bb f1 00 00',
		'< a0 06 00 a6 b0 03 00 32 01 c4',
		'> bb f1 00 00',
		'< a0 14 00 b4 32 11 00 02 00 3f 00 c5 00 fc 00 b6 00 e1 00 d7 00 f7 00 00',

		'> cc f2 44 82 a0 06 00 a6 20 03 00 01 00 86',
		'> bb f1 00 00',
		'< a0 06 00 a6 b0 03 00 20 01 d6',
		'> bb f1 00 00',
		##	[
		'< b0 45 1e 13 17 03 03 1e 40 9a 71 70 41 ae 7c d7 75 05 51 5a 51 08 22 a7 40 79 bd 28 a7 4e 1a 75 07 e6 e1 e2 ab 83 ca 93 1e 2e bc 9d ab d8 2e 67 2b c3 eb f6 f8 0b 74 e4 87 29 69 41 55 86 84 28 f6 b3 84 93 cc bc 55 62 4c 78 c2 e7 d3 80 c3 6a 13 38 de 7a 65 86 a0 55 a1 6f c2 19 08 ed d1 e7 13 db f7 bc ad ef 1a 44 52 b8 bb f5 c3 79 d7 9a a7 76 da 0f 30 91 f3 e7 f0 8d 5f c7 38 db ff 1f 12 33 9f 30 12 87 e7 56 d4 88 6f 02 aa 71 68 fc c1 78 95 5b fb ea 89 99 26 60 47 fa 85 5a b2 44 89 9d f7 cd 9f 0c 1a 92 8e dd cb bb d8 49 03 be f3 27 93 c5 15 26 93 69 bc f7 13 02 e4 7d 23 5b 67 3a 4a 34 b7 72 0f 9d 7b 38 6a 43 6f 10 84 c3 a3 df 24 7c 78 83 50 56 5a a1 e7 e7 92 9c 92 6a c1 f1 70 24 a2 5c c3 7d 69 c9 bc 5f 31 04 c5 e5 8a 46 3c 6d ac e8 f1 e4 ba 67 52 9c 41 75 06 66',
		'> bb f1 00 00',
		##	] ...32 times total, see above.

		'> cc f2 45 82 a0 12 00 b2 34 0f 00 0e 01 80 7d 80 99 80 76 80 8b 80 86 80 96 25',
		'> bb f1 00 00',
		'< a0 06 00 a6 b0 03 00 34 01 c2',

		'> cc f2 46 82 a0 12 00 b2 36 0f 00 0d 01 80 ac 80 bc 80 a0 80 b1 80 a3 80 b2 49',
		'> bb f1 00 00',
		'< a0 06 00 a6 b0 03 00 36 01 c0',
		'> bb f1 00 00',
		'< a0 14 00 b4 36 11 00 00 01 3f 00 b9 00 ed 00 ab 00 d2 00 c7 00 eb 00 4e',

		# <...>

		'> cc f2 4a 82 a0 06 00 a6 50 03 00 01 00 56',
		'> bb f1 00 00',
		'< a0 06 00 a6 b0 03 00 50 01 a6',
		'> bb f1 00 00',
		##	[
		'< a0 6d 09 16 50 6a 09 00 00 00 00 00 09 84 ec 98 a2 89 3a 73 88 a9 ab 7a 4a a3 cc ab ae 8a ba e3 ff aa b1 ca 8b 1b 3b b2 b3 bb 7b 43 54 b3 b4 8b 3b 47 47 b4 b6 8b 8b 6c 7b b4 b7 7b 4b 67 88 b7 ba 8b 0b 7c 88 b6 b8 8b cb 9f 70 b7 ba fb bb 90 8f b9 b8 8b 0b 9b 9b b9 bc 4b 0b 7f 9c b9 b8 bb 0b 9f 8f bb b7 7b 8b 5f a0 b1 aa 3a 79 53 e8 95 a2 89 3a 67 a0 a8 a9 fa ca ab b4 aa ac 0a ca d4 ff ab b0 0a ca ef 2c b0 b3 4b 3b 28 33 b3 b2 cb fb 47 27 b2 b4 cb 7b 38 63 b5 b7 7b cb 68 64 b6 b7 0b 8b 60 5c b6 b6 4b 8b 80 60 b6 b8 3b fb 53 68 b8 b5 0b 0b 83 67 b6 b9 0b fb 83 6f b4 b7 bb 4b 7b 6b b6 b6 3b 4b 2f 80 af a8 3a f9 6b 1c 96 a4 4a ba 68 77 a6 a9 8a 8a a3 b0 ac ae 0a 7a d4 0b af b0 cb 0a f3 0b b1 b1 7b 7b 4b 4f b2 b3 fb cb 50 43 b4 b3 7b 8b 73 63 b6 b6 cb 4b 6f 64 b6',
		##	] splits into multiple (11) packets on the bus, separated by host's RTRs. Undecodeable yet.

		# <...>

		'> cc f2 bd 82 a0 12 00 b2 34 0f 00 0e 01 80 76 80 98 80 79 80 84 80 78 80 88 4d',
		'> bb f1 00 00',
		'< a0 06 00 a6 b0 03 00 34 01 c2',
		'> bb f1 00 00',
		'< a0 14 00 b4 34 11 00 00 02 00 00 58 01 7a 01 41 01 62 01 47 01 64 01 3d',

		'> cc f2 92 23 a0 09 00 a9 ae 06 00 55 db 53 00 00 73',
	): decode_dump(i, errors=False)

# by Sdore, 2021
# www.sdore.me
