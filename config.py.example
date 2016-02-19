# NOTE: You must set the correct values before starting honeypot and save this
#       file as config.py. You must also generate some cryptographic keys and
#       configure iptables (see README.md for full setup instructions).

# IP to listen on. If you are behing NAT, this must be the private IP.
LOCAL_IP = '192.168.1.123'

# iptables must be configured to redirect all incoming TCP connections to this
# port (see README.md)
TCP_MAGIC_PORT = 1211

# Some LAN devices can be quite noisy. UDP packets from IPs listed here are
# ignored. If unsure, leave this list initially empty and fill it later if
# you see UDP spam from LAN devices.
UDP_DISCARD_FROM = [ ]
#UDP_DISCARD_FROM = [ '192.168.1.1', '192.168.1.4' ]

# HTTP CONNECT requests for the following ports will not succeed
HTTP_CONNECT_FORBIDDEN_PORTS = [ ]
#HTTP_CONNECT_FORBIDDEN_PORTS = [ 25 ]
