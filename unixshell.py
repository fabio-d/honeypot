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

import re, shlex, sys
from utils import readline

def process_commandline(socket, commandline):
	if commandline.strip() == '':
		return

	echomatch = re.match('.*echo (-[^ ]* )*([^-].*)', commandline)
	echomatch = shlex.split(echomatch.group(2)) if echomatch else None

	busyboxmatch = re.match('.*busybox +([^ ]*)', commandline)
	busyboxmatch = busyboxmatch.group(1) if busyboxmatch else None

	if echomatch:
		if 'busybox' in commandline:
			socket.send('Busybox v1.01 (2014.08.14-10:49+0000) Built-in shell (ash)\n')
			socket.send('Enter \'help\' for a list of built-in commands.\n\n')
			socket.send('Usage: busybox [function] [arguments]...\n')
			socket.send('   or: [function] [arguments]...\n\n')
			socket.send('        BusyBox is a multi-call binary that combines many common Unix\n')
			socket.send('        utilities into a single executable.  Most people will create a\n')
			socket.send('        link to busybox for each function they wish to use and BusyBox\n')
			socket.send('        will act like whatever it was invoked as!\n\n')
			socket.send('Currently defined functions:\n')
			socket.send('        [, arping, ash, awk, busybox, cat, chmod, cp, crond, cut, date, dd, df, dhcprelay, dmesg, dumpleases,\n')
			socket.send('        echo, egrep, expr, false, fgrep, find, free, fuser, grep, head, hexdump, ifconfig, init, insmod, kill,\n')
			socket.send('        killall, klogd, ln, logger, login, ls, lsmod, makedevs, md5sum, mkdir, mkfifo, mknod, mktemp, mount,\n')
			socket.send('        mv, nc, netstat, ping, ping6, printf, ps, reboot, rm, rmdir, rmmod, route, sed, sh, sleep, sort, sync,\n')
			socket.send('        sysctl, syslogd, tail, tar, telnet, telnetd, test, tftp, touch, tr, traceroute, true, udhcpc, udhcpd,\n')
			socket.send('        umount, uname, vconfig, vi, wc, wget, which\n\n')
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
		socket.send('  300 pts/9    S      0:00 /usr/sbin/sshd\n')
		socket.send('  892 pts/9    S      0:00 /usr/bin/bash\n')
		socket.send(' 1271 pts/9    S      0:00 /usr/sbin/httpd\n')
		socket.send(' 1325 pts/9    S      0:00 /usr/sbin/mysqld\n')
		socket.send('13628 pts/9    S      0:00 /usr/sbin/vftpd\n')
		socket.send('45378 pts/9    S      0:00 /usr/sbin/syslogd\n')
		socket.send('45982 pts/9    R+     0:00 /usr/bin/{}\n'.format(commandline))
	elif commandline == 'id':
		socket.send('uid=0(root) gid=0(root) groups=0(root)\n')
	elif commandline == 'sh' or commandline == 'shell':
		socket.send('\n')
	elif 'cat /proc/version' in commandline:
		socket.send('Linux version 2.4.6 (root@localhost) (gcc version 4.4.6 (GNU)) #9 Tue Jan 21 18:03:27 CST 2012\n')
	elif busyboxmatch:
		socket.send('{}: applet not found\n'.format(busyboxmatch))
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

if __name__ == "__main__":
	class DummyChannel(object):
		def recv(self, *args, **kw):
			return sys.stdin.read(*args, **kw)
		def send(self, *args, **kw):
			return sys.stdout.write(*args, **kw)
		def fileno(self):
			return sys.stdin.fileno()
	interactive_shell(DummyChannel(), '[user@localhost ~]$ ')
