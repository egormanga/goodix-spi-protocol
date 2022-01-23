#!/usr/bin/env python3

import time, periphery

for pin in (8, 3+8, 0x58, 152+8, 0x105):
	print(pin, end=': ')
	reset = periphery.CdevGPIO('/dev/gpiochip0', pin, 'out', bias='pull_up')
	print(reset.name)
	for i in (0, 1):
		reset.write(bool(i))
		time.sleep(0.03)
	reset.close()

exit()  # XXX

poll = periphery.CdevGPIO('/dev/gpiochip0', 3, 'in', bias='default')
#poll = periphery.CdevGPIO('/dev/gpiochip0', 152+0, 'in', bias='default')
print(poll.name)
while (True):
	r = poll.read()
	if (not r): print(r)
