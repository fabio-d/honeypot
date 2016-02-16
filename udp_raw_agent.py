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

import os, re, select, socket, sys, struct
import inetutils, ip, udp # from pyip
import pcap # from pylibpcap

local_ip = sys.argv[1]
caller_uid = int(sys.argv[2])
caller_gid = int(sys.argv[3])

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
except socket.error, msg:
	print('ERR Raw socket could not be created: {}'.format(msg[1]))
	sys.exit(1)

try:
	out_sk.bind((local_ip, 0))
except socket.error, msg:
	print('ERR Raw socket could not be bound to {}: {}'.format(local_ip, msg[1]))
	sys.exit(1)

p = pcap.pcapObject()
p.open_live(dev, 65535, 0, 100)
p.setfilter('udp and dst host {}'.format(local_ip), 0, 0)

try:
	os.setgid(caller_gid)
	os.setuid(caller_uid)
except OSError:
	print('ERR Could not drop privileges')
	sys.exit(1)

sys.stdout.write("OK -- {} -- Format: their_addr their_port our_port data\n".format(dev))
sys.stdout.flush()

def incoming_packet_handler(pktlen, data, timestamp):
	if not data or data[12:14] != '\x08\x00':
		return

	ip_pkt = ip.disassemble(data[14:])
	udp_frag = udp.disassemble(ip_pkt.data, False)
	data_str = udp_frag.data.encode('hex') if udp_frag.data != '' else '-'
	sys.stdout.write("{} {} {} {}\n".format(ip_pkt.src, udp_frag.sport, udp_frag.dport, data_str))
	sys.stdout.flush()

def outgoing_packet_handler(src_port, dst_addr, dst_port, data):
	udp_frag = udp.Packet(sport=src_port, dport=dst_port, data=data)
	udp_assembled = udp.assemble(udp_frag, False)
	pseudo_header = socket.inet_aton(local_ip) + socket.inet_aton(dst_addr) + '\x00\x11' + struct.pack('!H', len(udp_assembled))
	cksum = inetutils.cksum(pseudo_header + udp_assembled)
	udp_assembled_with_cksum = udp_assembled[:6] + struct.pack('H', cksum) + udp_assembled[8:]
	out_sk.sendto(udp_assembled_with_cksum, (dst_addr, 0))

try:
	while True:
		rlist, _, _ = select.select([p, sys.stdin], [], [], None)

		if p in rlist:
			p.dispatch(1, incoming_packet_handler)
		if sys.stdin in rlist:
			line = sys.stdin.readline().strip()
			if line == '':
				break

			dst_addr_str, dst_port_str, src_port_str, data_hex = line.split(' ', 3)
			data = data_hex.decode('hex') if data_hex != '-' else ''
			outgoing_packet_handler(int(src_port_str), dst_addr_str, int(dst_port_str), data)
except KeyboardInterrupt:
	pass
