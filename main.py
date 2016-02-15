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

import datetime, select, socket, SocketServer, struct, subprocess, sys, threading, time, traceback
from termcolor import colored

from tcp_ssh import handle_tcp_ssh
from tcp_telnet import handle_tcp_telnet
from tcp_http_https import handle_tcp_http, handle_tcp_https
from tcp_hexdump import handle_tcp_hexdump, handle_tcp_hexdump_ssl

LOCAL_IP = '192.168.1.123'
TCP_MAGIC_PORT = 1211

SSL_CLIENT_HELLO_SIGNATURES = [
	'\x16\x03\x03', # TLS v1.2
	'\x16\x03\x02', # TLS v1.1
	'\x16\x03\x01', # TLS v1.0
	'\x16\x03\x00', # SSL v3.0
	'\x16\x02\x00' # SSL v2.0
]

def handle_tcp(socket, dstport):
	handler = tcp_handlers.get(dstport, handle_tcp_default)
	try:
		handler(socket, dstport)
	except Exception as err:
		print(traceback.format_exc())
	socket.close()

tcp_handlers = {
	22: handle_tcp_ssh,
	23: handle_tcp_telnet,
	80: handle_tcp_http,
	443: handle_tcp_https,
	8080: handle_tcp_http
}

def handle_tcp_default(sk, dstport):
	# Attempt to guess protocol according to what the client sends
	data = ''
	try:
		rlist, _, _ = select.select([sk], [], [], 30)
		if len(rlist) != 0:
			data = sk.recv(20, socket.MSG_PEEK)
	except Exception as err:
		print(traceback.format_exc())
		pass

	if data[:3] in SSL_CLIENT_HELLO_SIGNATURES:
		print colored("Guessing this is a SSL/TLS connection, attempting to handshake.", 'red', attrs=['bold'])
		handle_tcp_hexdump_ssl(sk, dstport)
	elif data.startswith("GET "):
		handle_tcp_http(sk, dstport)
	else:
		handle_tcp_hexdump(sk, dstport)
	sk.close()

class SingleTCPHandler(SocketServer.BaseRequestHandler):
	def handle(self):
		# self.request is the socket
		timestr = datetime.datetime.now().strftime("%a %Y/%m/%d %H:%M:%S%z")
		srcaddr, srcport = self.request.getpeername()
		dstaddr, dstport = self.getoriginaldest()
		if dstaddr == LOCAL_IP:
			print colored("[{}]: Intruder {}:{} connected to fake port {}/tcp".format(timestr, srcaddr, srcport, dstport), 'magenta', attrs=['bold'])
			handle_tcp(self.request, dstport)
		else:
			print colored("[{}]: Unexpected connection from {}:{} to {}:{}/tcp. Closing it.".format(timestr, srcaddr, srcport, dstaddr, dstport), 'magenta', attrs=['bold'])
			self.request.send("Get out!\n")
			self.request.close()

	def getoriginaldest(self):
		SO_ORIGINAL_DST = 80
		odestdata = self.request.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
		_, port, a1, a2, a3, a4 = struct.unpack("!HHBBBBxxxxxxxx", odestdata)
		address = "%d.%d.%d.%d" % (a1, a2, a3, a4)
		return address, port

class SimpleServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
	daemon_threads = True
	allow_reuse_address = True

	def __init__(self, server_address, RequestHandlerClass):
		SocketServer.TCPServer.__init__(self, server_address, RequestHandlerClass)

try:
	try:
		server = SimpleServer(('0.0.0.0', TCP_MAGIC_PORT), SingleTCPHandler)
	except:
		server = None
		print(traceback.format_exc())

	if server:
		server.serve_forever()
except KeyboardInterrupt:
	pass

sys.exit(0)
