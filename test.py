#!/usr/bin/env python3

import time, spidev, struct

def calc_checksum(pid, payload):
	return ((0xaa - (sum(struct.pack('BH', pid, len(payload)+1)+payload) % 256)) % 256)
	#l = len(payload)
	#sum = pid
	#sum = (sum + ((l+1) & 0xff)) % 256
	#sum = (sum + (((l+1) >> 8) & 0xff)) % 256
	#for i in payload:
	#	sum = (sum + i) % 256
	#return (0xaa - sum) % 256

def xfer(data, *, recv=True):
	print('\033[94m> '+' '.join('%02x' % i for i in data)+'\033[0m')
	spi.xfer2(data)
	if (not recv): return
	while (True):
		r = bytes(spi.readbytes(256))
		if (not r.strip(b'\0')): time.sleep(0.001); continue
		print('\033[92m< '+' '.join('%02x' % i for i in r.rstrip(b'\0'))+'\033[0m')
		break

def send(pid, payload, **kwargs):
	payload = bytes.fromhex(payload)
	l = len(payload)
	data = bytearray(struct.pack('<BH', pid, l+1) + payload)
	data.append(calc_checksum(pid, payload))
	return xfer(data, **kwargs)

if (__name__ == '__main__'):
	spi = spidev.SpiDev(0, 0)

	#while (True):
	#	print(bytes(spi.readbytes(65535)))
	#	time.sleep(0.001)

	send(0x00, '00 00', recv=False)
	xfer(bytes.fromhex('cc f2 00 82   a0 06 00 a6   00 03 00 00 00 a7   00 00'), recv=False)
	#for i in range(256):
	xfer(bytes.fromhex('cc f2 01 82   a0 09 00 a9   ae 06 00 55 0e 52 00 00 41   00 00 00'), recv=False)

	#xfer(bytes.fromhex('cc f2 00 82   a0 14 00 b4   32 11 00 0c 01 80 ab 80 bc 80 a0 80 ae 80 a3 80 b0 f1 6c f5'), recv=False)

	#xfer(bytes.fromhex('cc f2 b4 ae   a0 14 00 b4   32 11 00 0c 01 80 ae 80 bf 80 a1 80 b2 80 a4 80 b3 05 44 fa'), recv=False)

	#xfer(bytes.fromhex('cc f2 01 82   a0 06 00 a6   20 03 00 01 00 86   00 00'), recv=False)

	#xfer(bytes.fromhex('cc f2 b6 ae a0 12 00 b2 34 0f 00 0e 01 80 98 80 be 80 83 80 92 80 84 80 9d cc 00 00'), recv=False)
	#send(0xa8, '00 00')

	#for i in range(32):
	xfer(bytes.fromhex('bb f1 00 00'))
	#	time.sleep(0.001)
