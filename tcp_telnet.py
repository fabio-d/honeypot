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

import re, select, shlex, socket, testrun, time

def readline(socket, echo, timeout=None):
	if timeout != None:
		timeout += time.time()

	buff = ''
	while buff.endswith('\n') == False:
		if timeout:
			remaining_time = timeout - time.time()
			if remaining_time <= 0:
				break

			rlist, _, _ = select.select([socket], [], [], remaining_time)
			if len(rlist) == 0:
				break

		c = socket.recv(1)
		if len(c) != 1:
			break

		if echo:
			socket.send(c)
		buff += c

	return buff

def process_commandline(socket, commandline):
	if commandline.strip() == '':
		return

	echomatch = re.match('echo (-[^ ]* )*([^-].*)', commandline)
	echomatch = shlex.split(echomatch.group(2)) if echomatch else None
	if echomatch:
		socket.send('{}\n'.format(' '.join(echomatch)).decode("string_escape"))
	elif 'uname' in commandline:
		socket.send('Linux\n')
	elif 'free' in commandline:
		socket.send('              total        used        free      shared  buff/cache   available\n')
		socket.send('Mem:          15950        3611        4905        1142        7432       11041\n')
		socket.send('Swap:          3071           0        3071\n')
	elif 'ps' in commandline:
		socket.send('  PID TTY      STAT   TIME COMMAND\n')
		socket.send('    1 pts/9    S      0:00 init\n')
		socket.send('  892 pts/9    S      0:00 bash\n')
		socket.send(' 1271 pts/9    S      0:00 httpd\n')
		socket.send(' 1325 pts/9    S      0:00 mysqld\n')
		socket.send('13628 pts/9    S      0:00 vftpd\n')
		socket.send('45378 pts/9    S      0:00 syslogd\n')
		socket.send('45982 pts/9    R+     0:00 {}\n'.format(commandline))
	else:
		firstword = commandline.split(' ', 1)[0]
		socket.send("sh: {}: command not found\n".format(firstword))

def interactive_shell(socket, ps1, linetimeout=None):
	for i in range(8):
		socket.send(ps1)
		cmdline = readline(socket, True, linetimeout).strip()
		if cmdline == 'exit':
			break

		process_commandline(socket, cmdline)

def handle_tcp_telnet(socket, dstport):
	socket.send("Linux-x86/2.4\nSamsung Smart TV\n\nlocalhost login: ")
	username = readline(socket, True).strip()

	if 'root' in username:
		ps1a = 'root@localhost:~# '
		ps1b = 'sh-4.3# '
	else:
		ps1a = '{}@localhost:~$ '.format(username)
		ps1b = 'sh-4.3$ '

	socket.send("Password: ")
	readline(socket, False, 8)

	socket.send("\n\nSuccessfully logged in. Log in successful.\n")
	socket.send("Busybox v1.01 (2014.08.14-10:49+0000) Built-in shell (ash)\n")
	socket.send("Enter 'help' for a list of built-in commands.\n\n{}".format(ps1a))
	process_commandline(socket, readline(socket, True, 10).strip())

	interactive_shell(socket, ps1b, 10)

	socket.close()

if __name__ == "__main__":
	testrun.run(2323, 23, handle_tcp_telnet)
