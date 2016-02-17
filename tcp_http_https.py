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

import re, socket, ssl, testrun, time, traceback, uuid
from utils import TextChannel, log_append, readline, switchtossl

# Adapted from 2.7/Lib/Cookie.py
def __getexpdate(future=0):
	weekdayname = [ 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun' ]
	monthname = [ None, 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec' ]
	year, month, day, hh, mm, ss, wd, y, z = time.gmtime(time.time() + future)
	return "%s, %02d %3s %4d %02d:%02d:%02d GMT" % (weekdayname[wd], day, monthname[month], year, hh, mm, ss)

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
			user_agent = ''
			while True:
				header = readline(socket).strip()
				if header == '':
					break
				elif header.upper() == 'CONNECTION: KEEP-ALIVE':
					keep_alive = True
				elif header.upper().startswith('USER-AGENT: '):
					user_agent = header[len('USER-AGENT: '):]

			session_token = uuid.uuid4().hex
			log_append('tcp_http_requests', socket.getpeername()[0], dstport, verb, url, user_agent, session_token)

			socket.send("HTTP/1.0 200 OK\nServer: microhttpd (MontaVista/2.4, i386-uClibc)\nSet-Cookie: sessionToken={}; Expires={}\nContent-Type: text/html\nContent-Length: 38\nConnection: {}\n\nmicrohttpd on Linux 2.4, it works!\n\n".format(session_token, __getexpdate(5 * 365 * 24 * 60 * 60), "keep-alive" if keep_alive else "close"))
	except ssl.SSLError as err:
		print("SSL error: {}".format(err.reason))
		pass
	except Exception as err:
		#print(traceback.format_exc())
		pass

	try:
		print("-- HTTP TRANSPORT CLOSED --")
		socket.close()
	except:
		pass

def handle_tcp_https(socket, dstport):
	plaintext_socket = switchtossl(socket)
	if plaintext_socket:
		handle_tcp_http(plaintext_socket, dstport)
	else:
		socket.close()

if __name__ == "__main__":
	#testrun.run_tcp(8080, 80, handle_tcp_http)
	testrun.run_tcp(8443, 443, handle_tcp_https)
