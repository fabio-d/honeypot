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

import datetime, select, sys, ssl, time, traceback
from termcolor import colored

class TextChannel(object):
	def __init__(self, chan, tee_target=sys.stderr, fix_incoming_endl=False):
		self.chan = chan
		self.tee_target = tee_target
		self.fix_incoming_endl = fix_incoming_endl
	def __get__(self, obj, type=None):
		return self.__class__(self.chan.__get__(obj, type))
	def __getattr__(self, name):
		return getattr(self.chan, name)
	def __call__(self, *args, **kw):
		return self.chan(*args, **kw)
	def recv(self, *args, **kw):
		buff = self.chan.recv(*args, **kw)
		if self.fix_incoming_endl:
			buff = buff.replace('\r', '\n')
		self.prettyprint(buff.replace('\r', ''), 'red', 'on_yellow')
		return buff
	def send(self, buff):
		buff = buff.replace('\n', '\r\n')
		r = self.chan.send(buff)
		self.prettyprint(buff[0:r], 'blue', 'on_cyan')
		return r
	def prettyprint(self, text, *oargs, **kw):
		text = text.replace('\r\n', '\n').replace('\r','\n')
		lines = text.split('\n')
		for i in range(len(lines)):
			if i != 0:
				self.tee_target.write('\n')
			self.tee_target.write(colored(lines[i], *oargs, **kw))

def noexceptwrap(func):
	def wrapped(*args, **kw):
		try:
			func(*args, **kw)
		except:
			#print(traceback.format_exc())
			pass
	return wrapped

def readline(socket, echo=False, timeout=None):
	if timeout != None:
		timeout += time.time()

	buff = ''
	to_be_echoed = ''
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
			to_be_echoed += c

			# Only flush when there is not further available input data
			rlist, _, _ = select.select([socket], [], [], 0)
			if len(rlist) == 0:
				socket.send(to_be_echoed)
				to_be_echoed = ''
		buff += c

	if len(to_be_echoed) != 0:
		socket.send(to_be_echoed)
	return buff

def switchtossl(socket):
	try:
		res = ssl.wrap_socket(socket, "tcp_ssl.key", "tcp_ssl_cert.pem", True)
		print("SSL handshake completed")
		return res
	except Exception as err:
		#print(traceback.format_exc())
		return None

def log_append(log_name, *columns):
	data = list(str(e) for e in columns)
	data.append(datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S%z"))
	try:
		with open("logs/{}.txt".format(log_name), "a") as logfile:
			logfile.write("{}\n".format(','.join(data)))
	except IOError as err:
		print "log_append failed:", err
