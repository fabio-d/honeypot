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

import random, re, select, socket, sys, struct
import ip, udp # from pyip
import pcap # from pylibpcap

local_ip = sys.argv[1]

def ip4_str_to_num(ip):
	return struct.unpack('>L', socket.inet_aton(ip))[0]

def search_if_by_ip(ip_str):
	search_addr = ip4_str_to_num(ip_str)

	for dev in pcap.findalldevs():
		name, _, addresses, _ = dev

		for (addr, netmask, _, _) in addresses:
			if re.match("[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", addr):
				addr_num = ip4_str_to_num(addr)
				netmask_num = ip4_str_to_num(netmask)
				if (addr_num & netmask_num) == (search_addr & netmask_num):
					return name

	return None

dev = search_if_by_ip(local_ip)

if not dev:
	print('ERR Cannot find interface for {}'.format(local_ip))
	sys.exit(1)

try:
	out_sk = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
	out_sk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	out_sk.bind((local_ip, 0))
except socket.error, msg:
	sys.stdout.write('ERR Socket could not be created: {}\n'.format(msg[1]))
	sys.exit(1)

p = pcap.pcapObject()
p.open_live(dev, 65535, 0, 100)
p.setfilter('udp and dst host {}'.format(local_ip), 0, 0)

print "OK -- {} -- Format: their_addr their_port our_port data".format(dev)

def incoming_packet_handler(pktlen, data, timestamp):
	if not data or data[12:14] != '\x08\x00':
		return

	ip_pkt = ip.disassemble(data[14:])
	udp_frag = udp.disassemble(ip_pkt.data, False)
	print ip_pkt.src, udp_frag.sport, udp_frag.dport, udp_frag.data.encode('hex')

def outgoing_packet_handler(src_port, dst_addr, dst_port, data):
	udp_frag = udp.Packet(sport=src_port, dport=dst_port, data=data)
	out_sk.sendto(udp.assemble(udp_frag, False), (dst_addr, 0))

while True:
	rlist, _, _ = select.select([p, sys.stdin], [], [], None)

	if p in rlist:
		p.dispatch(1, incoming_packet_handler)
	if sys.stdin in rlist:
		line = sys.stdin.readline().strip()
		if line == '':
			break
		dst_addr_str, dst_port_str, src_port_str, data_hex = line.split(' ', 3)
		outgoing_packet_handler(int(src_port_str), dst_addr_str, int(dst_port_str), data_hex.decode('hex'))
