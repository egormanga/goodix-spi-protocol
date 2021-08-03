#!/usr/bin/env python3

import periphery

#reset = periphery.CdevGPIO('/dev/gpiochip0', 8, 'out', bias='pull_up')
#reset = periphery.CdevGPIO('/dev/gpiochip0', 0x5E, 'out', bias='pull_up')
reset = periphery.CdevGPIO('/dev/gpiochip0', 152+8, 'out', bias='pull_up')
print(reset.name)
reset.write(True)

exit()  # XXX

#poll = periphery.CdevGPIO('/dev/gpiochip0', 3, 'in', bias='default')
poll = periphery.CdevGPIO('/dev/gpiochip0', 152+3, 'in', bias='default')
print(poll.name)
while (True):
	r = poll.read()
	if (not r): print(r)
