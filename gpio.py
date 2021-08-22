#!/usr/bin/env python3

import time, periphery

reset = periphery.CdevGPIO('/dev/gpiochip0', 8, 'out', bias='pull_up')
#reset = periphery.CdevGPIO('/dev/gpiochip0', 0x5E, 'out', bias='pull_up')
#reset = periphery.CdevGPIO('/dev/gpiochip0', 11, 'out')
print(reset.name)
for i in (1, 0, 1, 0, 1, 0, 1):
	reset.write(bool(i))
	time.sleep(0.1)

exit()  # XXX

poll = periphery.CdevGPIO('/dev/gpiochip0', 3, 'in', bias='default')
#poll = periphery.CdevGPIO('/dev/gpiochip0', 152+0, 'in', bias='default')
print(poll.name)
while (True):
	r = poll.read()
	if (not r): print(r)
