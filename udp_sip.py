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

import StringIO, re, testrun, threading, time, uuid
from termcolor import colored
from utils import log_append, tee_received_text, tee_sent_text

USER_AGENT = 'Linphone/3.5.2 (eXosip2/3.6.0)'
#USER_AGENT = 'Asterix PBX'

# In order to fool svwar, we have to pretend the very first request failed
# This table stores the 'To' value we saw in the first request, as well as the
# timestamp. Entries are removed after 10 seconds
BAD_USER_lock = threading.Lock()
BAD_USER_BY_IP = {}
def is_bad_user(srcaddr, username):
	BAD_USER_lock.acquire()
	# Expire if too old
	if srcaddr in BAD_USER_BY_IP and time.time() - BAD_USER_BY_IP[srcaddr][1] > 10:
		del BAD_USER_BY_IP[srcaddr]

	if srcaddr in BAD_USER_BY_IP:
		baduser = BAD_USER_BY_IP[srcaddr][0]
	else:
		baduser = username

	BAD_USER_BY_IP[srcaddr] = (baduser, time.time())
	BAD_USER_lock.release()

	return username == baduser

SIPVICIOUS_NONE = 0
SIPVICIOUS_SVMAP = 1
SIPVICIOUS_SVWAR = 2
def detect_sipvicious(from_value, dstport):
	rematch = re.match("\"([^\"]+)\".*; ?tag=([0-9a-z]+)", from_value)
	if not rematch or len(rematch.group(2)) % 2 != 0:
		return SIPVICIOUS_NONE

	if rematch.group(2)[16:26] == ("%04x" % dstport).encode('hex') + '01':
		if '1.1.1.1' in from_value or 'sipvicious' in from_value:
			return SIPVICIOUS_SVMAP
		else:
			return SIPVICIOUS_NONE

	if rematch.group(2).startswith(rematch.group(1).encode('hex') + '01'):
		return SIPVICIOUS_SVWAR

	return SIPVICIOUS_NONE

def handle_udp_sip(socket, data, srcpeername, dstport):
	input_stream = StringIO.StringIO(tee_received_text(data))
	firstline = input_stream.readline().strip()
	rematch = re.match("([A-Z]+) ([^ ]+) ?.*", firstline)

	if not rematch:
		raise Exception('Unexpected request')

	method = rematch.group(1)
	url = rematch.group(2)

	# Parse headers
	headers = {}
	while True:
		header = input_stream.readline().strip()
		if header == '':
			break
		else:
			rematch = re.match("([^:]+): ?(.*)", header)
			if not rematch:
				raise Exception('Unexpected header')
			else:
				headers[rematch.group(1)] = rematch.group(2)

	svtool = detect_sipvicious(headers['From'], dstport)

	# Send reply
	if (method == 'OPTIONS' or method == 'INVITE') and svtool == SIPVICIOUS_SVMAP:
		print("It looks like we are being scanned by svmap")
		resp = 'SIP/2.0 200 OK\n'
		rheaders = dict(headers)
		rheaders['To'] += ';tag=' + uuid.uuid4().hex
		rheaders['Allow'] = 'INVITE, ACK, BYE, CANCEL, OPTIONS, MESSAGE, SUBSCRIBE, NOTIFY, INFO'
		rheaders['User-Agent'] = USER_AGENT
	elif (method == 'REGISTER' or method == 'INVITE') and svtool == SIPVICIOUS_SVWAR:
		print("It looks like we are being scanned by svwar")
		if is_bad_user(srcpeername[0], headers['To']):
			print("Pretending {} is a bad user".format(headers['To']))
			resp = 'SIP/2.0 404 Not Found\n'
		else:
			print("Pretending {} is a good user".format(headers['To']))
			resp = 'SIP/2.0 200 OK\n'
		# http://kb.smartvox.co.uk/asterisk/friendlyscanner-gets-aggressive/
		rheaders = { 'From': headers['From'], 'To': headers['To'], 'Call-ID': headers['Call-ID'], 'CSeq': headers['CSeq'] }
		rheaders['Via'] = '{};received={}'.format(headers['Via'].replace(';rport', ''), srcpeername[0])
		rheaders['User-Agent'] = USER_AGENT
	elif method == 'INVITE':
		print("The intruder is trying to make a call")
		# Pretend we don't understand to stop further interactions
		resp = 'SIP/2.0 501 Not Implemented\n'
		rheaders = {}
		to_hdr = headers.get('To', '')
		from_hdr = headers.get('From', '')
		ua_hdr = headers.get('User-Agent', '')
		log_append('udp_sip_invites', srcpeername[0], to_hdr, from_hdr, ua_hdr)
	elif (method == 'ACK' or method == 'BYE'):
		resp = 'SIP/2.0 200 OK\n'
		rheaders = dict(headers)
		rheaders['User-Agent'] = USER_AGENT
	else:
		resp = 'SIP/2.0 501 Not Implemented\n'
		rheaders = {}

	# Assemble response
	for k in rheaders:
		resp += '{}: {}\n'.format(k, rheaders[k])
	socket.sendto(tee_sent_text('{}\n'.format(resp)), srcpeername)

if __name__ == "__main__":
	testrun.run_udp(5060, 5060, handle_udp_sip)
