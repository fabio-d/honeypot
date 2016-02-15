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

import testrun, time, traceback, uuid
from utils import TextChannel, readline, switchtossl

def receive_data(socket):
	while readline(socket).strip('\r\n') != '.':
		pass
	return "{}@localhost".format(uuid.uuid4().hex)

def handle_tcp_smtp(plaintext_socket, dstport):
	socket = TextChannel(plaintext_socket)
	tls_started = False

	try:
		socket.send("220 localhost ESMTP server ready\n")

		while True:
			cmd = readline(socket)
			cmdupper = cmd.upper() if cmd else None

			if not cmd or not cmd.endswith('\n'):
				raise Exception('Invalid request')
			elif cmdupper.startswith('HELO'):
				socket.send("250 localhost\n")
			elif cmdupper.startswith('EHLO'):
				socket.send("250-localhost offers TWO extensions:\n250-8BITMIME\n250 STARTTLS\n")
			elif cmdupper.startswith('STARTTLS'):
				if tls_started:
					socket.send("454 TLS not available due to temporary reason\n")
				else:
					tls_started = True
					socket.send("220 Go ahead\n")
					socket = TextChannel(switchtossl(plaintext_socket))
			elif cmdupper.startswith('QUIT'):
				socket.send("221 localhost ESMTP server closing connection\n")
				break
			elif cmdupper.startswith('NOOP'):
				socket.send("250 No-op Ok\n")
			elif cmdupper.startswith('RSET'):
				socket.send("250 Reset Ok\n")
			elif cmdupper.startswith('DATA'):
				socket.send("354 Ok Send data ending with <CRLF>.<CRLF>\n")
				socket.send("250 Message received: {}\n".format(receive_data(socket)))
			elif cmdupper.startswith('MAIL FROM:') or cmdupper.startswith('SEND FROM:') or cmdupper.startswith('SOML FROM:') or cmdupper.startswith('SAML FROM:'):
				socket.send("250 Sender: {} Ok\n".format(cmd[len('MAIL FROM:'):].strip()))
			elif cmdupper.startswith('RCPT TO:'):
				socket.send("250 Recipient: {} Ok\n".format(cmd[len('RCTP TO:'):].strip()))
			else:
				socket.send("502 Command not implemented\n")
	except Exception as err:
		#print(traceback.format_exc())
		pass

	try:
		print("-- SMTP TRANSPORT CLOSED --")
		socket.close()
	except:
		pass

if __name__ == "__main__":
	testrun.run(2525, 25, handle_tcp_smtp)
