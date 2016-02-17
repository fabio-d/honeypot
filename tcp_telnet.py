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

import re, shlex, testrun, traceback
from unixshell import interactive_shell, process_commandline
from utils import TextChannel, log_append, readline

def handle_tcp_telnet(socket, dstport):
	socket = TextChannel(socket)

	try:
		socket.send("Linux-x86/2.4\nSamsung Smart TV\n\nlocalhost login: ")
		username = readline(socket, True).strip()

		if 'root' in username:
			ps1a = 'root@localhost:~# '
			ps1b = 'sh-4.3# '
		else:
			ps1a = '{}@localhost:~$ '.format(username)
			ps1b = 'sh-4.3$ '

		socket.send("Password: ")
		password = readline(socket, False, 20).strip()
		log_append('tcp_telnet_passwords', username, password, *socket.getpeername())

		socket.send("\n\nSuccessfully logged in. Log in successful.\n")
		socket.send("Busybox v1.01 (2014.08.14-10:49+0000) Built-in shell (ash)\n")
		socket.send("Enter 'help' for a list of built-in commands.\n\n{}".format(ps1a))
		process_commandline(socket, readline(socket, True, 10).strip())

		interactive_shell(socket, ps1b, 10)
	except Exception as err:
		#print(traceback.format_exc())
		pass

	try:
		print("-- TELNET TRANSPORT CLOSED --")
		socket.close()
	except:
		pass

if __name__ == "__main__":
	testrun.run_tcp(2323, 23, handle_tcp_telnet)
