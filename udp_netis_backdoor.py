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

import StringIO, testrun
from tcp_telnet import process_commandline
from utils import tee_received_text, tee_sent_text
from termcolor import colored

def handle_udp_netis_backdoor(socket, data, srcpeername, dstport):
	if data.startswith('AAAAAAAAnetcore\x00'):
		print("Netis backdoor enable command received")
	elif data.startswith('AA\0\0AAAA'):
		print("Netis backdoor execute command received:")
		command = tee_received_text(data[8:].strip())
		print("")
		outstream = StringIO.StringIO()
		outstream.send = outstream.write # HACK
		process_commandline(outstream, command)
		socket.sendto(tee_sent_text(outstream.getvalue()), srcpeername)
	else:
		print("Unknown Netis backdoor command received:")
		print(data.encode("hex"))

if __name__ == "__main__":
	testrun.run_udp(53413, 53413, handle_udp_netis_backdoor)
