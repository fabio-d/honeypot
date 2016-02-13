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

def handle_http(socket, dstport):
	time.sleep(2)
	socket.send("HTTP/1.0 200 OK\r\nServer: microhttpd (MontaVista/2.4, i386-uClibc)\r\nContent-Type: text/html\r\nContent-Length: 34\r\nConnection: keep-alive\r\n\r\nmicrohttpd on Linux 2.4, it works!")

	time.sleep(10)
	socket.close()

if __name__ == "__main__":
	qtestlib.run(20049, 80, handle_http)
