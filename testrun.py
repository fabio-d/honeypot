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

import SocketServer, sys

def run_tcp(realport, fakeport, handler):
	class SingleTCPHandler(SocketServer.BaseRequestHandler):
		def handle(self):
			srcaddr, srcport = self.request.getpeername()
			print("Connection from {}:{}".format(srcaddr, srcport))
			handler(self.request, fakeport)

	class SimpleServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
		daemon_threads = True
		allow_reuse_address = True

		def __init__(self, server_address, RequestHandlerClass):
			SocketServer.TCPServer.__init__(self, server_address, RequestHandlerClass)

	server = SimpleServer(('127.0.0.1', realport), SingleTCPHandler)
	try:
		server.serve_forever()
	except KeyboardInterrupt:
		sys.exit(0)

def run_udp(realport, fakeport, handler):
	class SingleUDPHandler(SocketServer.BaseRequestHandler):
		def handle(self):
			srcaddr, srcport = self.client_address
			print("Packet from {}:{}".format(srcaddr, srcport))
			handler(self.request[1], self.request[0], self.client_address, fakeport)

	class SimpleServer(SocketServer.ThreadingMixIn, SocketServer.UDPServer):
		daemon_threads = True

		def __init__(self, server_address, RequestHandlerClass):
			SocketServer.UDPServer.__init__(self, server_address, RequestHandlerClass)

	server = SimpleServer(('127.0.0.1', realport), SingleUDPHandler)
	try:
		server.serve_forever()
	except KeyboardInterrupt:
		sys.exit(0)
