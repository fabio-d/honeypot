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

import StringIO, testrun
from unixshell import process_commandline
from utils import tee_received_text, tee_sent_text, tee_received_bin, tee_sent_bin
from termcolor import colored

VERSION_TEXT = 'netis(WF2880_US)-V1.2.29578,2014.09.05 16:34.\n'

HELP_TEXT = ('Usage: $Help\r\n'
	+ 'Usage: $WriteMac <macaddr> <lan|wan|wlan0|wlan0.1|wlan0.2|wlan0.3|wlan1|wlan1.1|wlan1.2|wlan1.3>\r\n'
	+ 'Usage: $ReadMac <lan|wan|wlan0|wlan0.1|wlan0.2|wlan0.3|wlan1|wlan1.1|wlan1.2|wlan1.3> [<str|STR>[separator]|bin]\r\n'
	+ 'Usage: $WriteSsid <ssidstr> [WLAN1|WLAN0_DEFAULT_SSID|WLAN0_WSC_SSID|REPEATER_SSID2|REPEATER_SSID1|WLAN1.1|WLAN0_VAP0_DEFAULT_SSID|WLAN0_VAP0_WSC_SSID|WLAN1.2|WLAN0_VAP1_DEFAULT_SSID|WLAN0_VAP1_WSC_SSID|WLAN1.3|WLAN0_VAP2_DEFAULT_SSID|WLAN0_VAP2_WSC_SSID|WLAN1.4|WLAN0_VAP3_DEFAULT_SSID|WLAN0_VAP3_WSC_SSID|WLAN1.5|WLAN0_VAP4_DEFAULT_SSID|WLAN0_VAP4_WSC_SSID]\r\n'
	+ 'Usage: $ReadSsid [WLAN1|WLAN0_DEFAULT_SSID|WLAN0_WSC_SSID|REPEATER_SSID2|REPEATER_SSID1|WLAN1.1|WLAN0_VAP0_DEFAULT_SSID|WLAN0_VAP0_WSC_SSID|WLAN1.2|WLAN0_VAP1_DEFAULT_SSID|WLAN0_VAP1_WSC_SSID|WLAN1.3|WLAN0_VAP2_DEFAULT_SSID|WLAN0_VAP2_WSC_SSID|WLAN1.4|WLAN0_VAP3_DEFAULT_SSID|WLAN0_VAP3_WSC_SSID|WLAN1.5|WLAN0_VAP4_DEFAULT_SSID|WLAN0_VAP4_WSC_SSID]\r\n'
	+ 'Usage: $GetVersion\r\n'
	+ 'Usage: $ReadRegDomain <wlan0|wlan1> [str|bin]\r\n'
	+ 'Usage: $WriteRegDomain <wlan0|wlan1> <1~14>\r\n'
	+ 'Usage: $ReadWwwPasswd\r\n'
	+ 'Usage: $WriteWwwPasswd <passwordstr>\r\n'
	+ 'Usage: $ReadChannel [str|bin]\r\n'
	+ 'Usage: $WriteChannel <0~16>\r\n'
	+ 'Usage: $ReadChannelBonding [str|bin]\r\n'
	+ 'Usage: $WriteChannelBonding <0|1>\r\n'
	+ 'Usage: $TestUsb\r\n'
	+ 'Usage: $SetSsid <interface> <ssidstr>\r\n'
	+ 'Usage: $GetSsid <interface>\r\n'
	+ 'Usage: $GetGpioStatus [str|bin]\r\n'
	+ 'Usage: $Ifconfig netif ip/mask\r\n'
	+ 'Usage: $CheckDev devname\r\n')

def handle_udp_netis_backdoor(socket, data, srcpeername, dstport):
	tee_received_bin(data)

	if data == '\n':
		print("Netis backdoor scan received")
		socket.sendto(tee_sent_bin('\n\0\0\6\0\1\0\0\0\0\320\245Login:'), srcpeername)
	elif data.startswith('AAAAAAAAnetcore\0'):
		print("Netis backdoor enable command received")
		socket.sendto(tee_sent_bin('AA\0\5ABAA\0\0\0\0Login successed!\r\n'), srcpeername) # sic
	elif data.startswith('AA\0\0AAAA?\0'):
		print("Netis backdoor version query received")
		socket.sendto(tee_sent_bin('AA\0\5ABAA\0\0\1\0IGD MPT Interface daemon 1.0\0'), srcpeername)
	elif data.startswith('AA\0\0AAAA$GetVersion\0'):
		print("Netis backdoor $GetVersion command received")
		socket.sendto(tee_sent_bin('AA\0\5ABAA\0\0\0\0{}'.format(VERSION_TEXT)), srcpeername)
	elif data.startswith('AA\0\0AAAA$Help\0'):
		print("Netis backdoor $Help command received")
		socket.sendto(tee_sent_bin('AA\0\5ABAA\0\0\1\0{}'.format(HELP_TEXT)), srcpeername)
	elif data.startswith('AA\0\0AAAA'):
		print("\nNetis backdoor execute command received:")
		command = tee_received_text(data[8:].strip())

		print("")
		outstream = StringIO.StringIO()
		outstream.send = outstream.write # HACK
		process_commandline(outstream, command)
		output = tee_sent_text(outstream.getvalue())
		print("\nAssembled reply packets:")

		marker = 'B'
		while len(output) > 0:
			curr_block = output[:1991]
			output = output[1991:]
			socket.sendto(tee_sent_bin('AA\0\4A{}AA{}'.format(marker, curr_block)), srcpeername)
			marker = chr(1 + ord(marker))
		socket.sendto(tee_sent_bin('AA\0\5A{}AA\0\0\0\0'.format(marker)), srcpeername)
	else:
		print("Unknown Netis backdoor command")

if __name__ == "__main__":
	testrun.run_udp(53413, 53413, handle_udp_netis_backdoor)
