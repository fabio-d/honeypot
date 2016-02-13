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

import qtestlib, socket, time

def read_to_endl(socket):
	while True:
		c = socket.recv(1)
		socket.send(c)
		if c == '\n':
			break

def handle_telnet(socket, dstport):
	socket.send("Linux-x86/2.4\nSamsung Smart TV\n\nlocalhost login: ")
	read_to_endl(socket)

	socket.send("Password: ")
	read_to_endl(socket)

	socket.send("\n\nSuccessfully logged in.\nLog in successful.\nLog in.\nBusybox\nUbuntu\n\nroot@localhost:~# ")
	time.sleep(2)

	socket.send("\nsh-4.3$ ")
	time.sleep(2)
	socket.close()

if __name__ == "__main__":
	qtestlib.run(2049, 23, handle_telnet)
