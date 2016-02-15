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

import re, socket, testrun, time, traceback, uuid
from utils import TextChannel, readline, switchtossl

def handle_tcp_http(socket, dstport):
	socket = TextChannel(socket)

	try:
		keep_alive = True
		while keep_alive:
			firstline = readline(socket).strip()
			rematch = re.match("([A-Z]+) ([^ ]+) ?.*", firstline)

			if not rematch:
				raise Exception('Unexpected request')

			verb = rematch.group(1)
			url = rematch.group(2)

			# Skip headers
			keep_alive = False
			while True:
				header = readline(socket).strip()
				if header == '':
					break
				elif header.upper() == 'CONNECTION: KEEP-ALIVE':
					keep_alive = True

			socket.send("HTTP/1.0 200 OK\nServer: microhttpd (MontaVista/2.4, i386-uClibc)\nSet-Cookie: sessionToken={}; Expires=Wed, 09 Jun 2021 10:18:14 GMT\nContent-Type: text/html\nContent-Length: 38\nConnection: {}\n\nmicrohttpd on Linux 2.4, it works!\n\n".format(uuid.uuid4().hex, "keep-alive" if keep_alive else "close"))

	except Exception as err:
		#print(traceback.format_exc())
		pass

	try:
		print("-- HTTP TRANSPORT CLOSED --")
		socket.close()
	except:
		pass

def handle_tcp_https(socket, dstport):
	socket = switchtossl(socket)
	if socket:
		handle_tcp_http(socket, dstport)

if __name__ == "__main__":
	#testrun.run(8080, 80, handle_tcp_http)
	testrun.run(8443, 443, handle_tcp_https)
