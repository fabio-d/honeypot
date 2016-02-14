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

import datetime, os, select, socket, SocketServer, struct, subprocess, sys, threading, time, traceback
from termcolor import colored

from tcp_ssh import handle_tcp_ssh
from tcp_telnet import handle_tcp_telnet
from tcp_smtp import handle_tcp_smtp
from tcp_http_https import handle_tcp_http, handle_tcp_https
from tcp_httpproxy import make_tcp_httpproxy_handler
from tcp_hexdump import handle_tcp_hexdump, handle_tcp_hexdump_ssl

from udp_hexdump import handle_udp_hexdump

LOCAL_IP = '192.168.1.123'
TCP_MAGIC_PORT = 1211
UDP_DISCARD_FROM = [ '192.168.1.1', '192.168.1.4' ]

# TCP DISPATCHER

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

handle_tcp_httpproxy = make_tcp_httpproxy_handler(handle_tcp)

tcp_handlers = {
	22: handle_tcp_ssh,
	23: handle_tcp_telnet,
	25: handle_tcp_smtp,
	#80: handle_tcp_http,
	443: handle_tcp_https,
	#8080: handle_tcp_http,
	8118: handle_tcp_httpproxy
}

def handle_tcp_default(sk, dstport):
	# Attempt to guess protocol according to what the client sends
	data = ''
	try:
		rlist, _, _ = select.select([sk], [], [], 30)
		if len(rlist) != 0:
			data = sk.recv(20, socket.MSG_PEEK)
	except Exception as err:
		#print(traceback.format_exc())
		pass

	if data[:3] in SSL_CLIENT_HELLO_SIGNATURES:
		print colored("Guessing this is a SSL/TLS connection, attempting to handshake.", 'red', attrs=['bold'])
		handle_tcp_hexdump_ssl(sk, dstport)
	elif data.startswith("GET "):
		handle_tcp_http(sk, dstport)
	elif data.startswith("CONNECT "):
		handle_tcp_httpproxy(sk, dstport)
	else:
		handle_tcp_hexdump(sk, dstport)
	sk.close()

# UDP DISPATCHER

def handle_udp(socket, data, srcpeername, dstport):
	handler = handle_udp_hexdump
	try:
		handler(socket, data, srcpeername, dstport)
	except Exception as err:
		print(traceback.format_exc())

# TCP CONNECTION ACCEPTANCE

class SingleTCPHandler(SocketServer.BaseRequestHandler):
	def handle(self):
		# self.request is the socket
		try:
			srcaddr, srcport = self.request.getpeername()
		except:
			# This may happen if the connection gets closed by the
			# peer while we are still spawning the thread to handle it
			return

		dstaddr, dstport = self.getoriginaldest()
		timestr = datetime.datetime.now().strftime("%a %Y/%m/%d %H:%M:%S%z")
		if dstaddr == LOCAL_IP:
			print colored("[{}]: Intruder {}:{} connected to fake port {}/tcp".format(timestr, srcaddr, srcport, dstport), 'magenta', attrs=['bold'])
			handle_tcp(self.request, dstport)
		else:
			print colored("[{}]: Unexpected connection from {}:{} to {}:{}/tcp. Closing it.".format(timestr, srcaddr, srcport, dstaddr, dstport), 'magenta', attrs=['bold'])
			self.request.send("You are connected to the wrong IP address, get out!\n")
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

# UDP PACKET HANDLING

udp_raw_agent_lock = threading.Lock()

class UDP_socketobject_proxy:
	def __init__(self, local_port):
		self.local_port = local_port

	def sendto(self, data, dest):
		dest_ip, dest_port = dest
		data_str = data.encode('hex') if data != '' else '-'
		udp_raw_agent_lock.acquire()
		udp_raw_agent.stdin.write('{} {} {} {}\n'.format(dest_ip, dest_port, self.local_port, data_str))
		udp_raw_agent.stdin.flush()
		udp_raw_agent_lock.release()

def process_incoming_udp(data, srcaddr, srcport, dstport):
	timestr = datetime.datetime.now().strftime("%a %Y/%m/%d %H:%M:%S%z")
	print colored("[{}]: Intruder {}:{} connected to fake port {}/udp".format(timestr, srcaddr, srcport, dstport), 'magenta', attrs=['bold'])
	handle_udp(UDP_socketobject_proxy(dstport), data, (srcaddr, srcport), dstport)

def udp_raw_agent_dispatcher(incoming_packets):
	while True:
		line = incoming_packets.readline().strip()
		if line == '':
			break

		src_addr, src_port_str, dst_port_str, data_hex = line.split(' ', 3)

		if src_addr in UDP_DISCARD_FROM:
			continue

		data = data_hex.decode('hex') if data_hex != '-' else ''
		threading.Thread(target=process_incoming_udp, args=[data, src_addr, int(src_port_str), int(dst_port_str)]).start()

# TCP AND UDP INITIALIZATION

# Start UDP raw agent (which must be run as root)
udp_raw_agent_command_line = [ './udp_raw_agent.py', LOCAL_IP, str(os.getuid()), str(os.getgid()) ]
if os.getuid() != 0:
	udp_raw_agent_command_line = ['sudo', '-k'] + udp_raw_agent_command_line
udp_raw_agent = subprocess.Popen(udp_raw_agent_command_line, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
firstline = udp_raw_agent.stdout.readline()
if firstline.startswith('OK') == False:
	if firstline.startswith('ERR '):
		print(firstline[len('ERR '):].strip())
	print("Error! UDP agent could not be started properly")
	sys.exit(1)

try:
	try:
		server = SimpleServer(('0.0.0.0', TCP_MAGIC_PORT), SingleTCPHandler)
	except:
		server = None
		print(traceback.format_exc())

	if server:
		print("Started successfully, waiting for intruders...")
		threading.Thread(target=udp_raw_agent_dispatcher, args=[udp_raw_agent.stdout]).start()
		server.serve_forever()
except KeyboardInterrupt:
	pass
finally:
	try:
		udp_raw_agent_lock.acquire()
		udp_raw_agent.stdin.close()
		udp_raw_agent_lock.release()
		udp_raw_agent.wait()
	except:
		print(traceback.format_exc())
		udp_raw_agent.terminate()
	sys.exit(0)
