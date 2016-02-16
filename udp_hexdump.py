#!/usr/bin/env python2
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import testrun
from termcolor import colored

def hexdump(src, length=16):
	FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
	lines = []
	for c in xrange(0, len(src), length):
		chars = src[c:c+length]
		hexstr = ' '.join(["%02x" % ord(x) for x in chars])
		printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
		lines.append("%04x  %-*s  %-*s" % (c, length*3, hexstr, length, printable))
	lines.append("%04x" % len(src))
	return lines

def handle_udp_hexdump(data, srcaddr, srcport, dstport):
	for line in hexdump(data):
		print colored(line, 'red', 'on_yellow')

#if __name__ == "__main__":
#	#testrun.run_udp(8888, 8888, handle_udp_hexdump)
