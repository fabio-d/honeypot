# honeypot
Yet another Python honeypot ;)

## About this project
This honeypot is designed to listen on **all** TCP and UDP ports. It emulates the following services:
 * SSH (`22/tcp`)
 * telnet (`23/tcp`)
 * SMTP (`25/tcp`)
 * HTTPS (`443/tcp` only)
 * HTTP GET and CONNECT (on every other `tcp` port)
 * SIP (`5060/udp`, with special support to detect [sipvicious](https://github.com/sandrogauci/sipvicious) scans)
 * Netis [factory backdoor](http://blog.trendmicro.com/trendlabs-security-intelligence/netis-routers-leave-wide-open-backdoor/)

HTTP is autodetected by monitoring whether the first bytes sent by the client are either `GET` or `CONNECT`. In case of HTTP CONNECT requests, the emulated proxy always loops back to the honeypot itself.

Similarly, SSL/TLS is also autodetected by checking if the first bytes sent by the client look like the first bytes of the `SSL Client Hello` handshake message.

Any other unrecognized TCP connection or UDP packet is logged as-is in hexdump-like form.

# Installation and setup

## Prerequisites
A Linux system with Python 2 and `iptables`, plus a few extra Python libraries:
 * Fedora packages: `python-termcolor`, `python-GeoIP`, `python-paramiko`, `pyip` and `pylibpcap`;
 * Ubuntu packages: `python-termcolor`, `python-geoip`, `python-paramiko`, `python-pyip` and `python-libpcap`.

## Configuration
 1. Copy `config.py.example` as `config.py`.
 2. Open and edit `config.py`:
     * `LOCAL_IP` must be set to the IP the honeypot will listen on (if you are behind NAT, this must be the private IP). The example texts in next section assume `LOCAL_IP` is 192.168.1.123 but, according to your network setup, you will probably use a different IP address. Change this value accordingly.
     * `TCP_MAGIC_PORT` is the TCP port where all TCP traffic is redirected to. There is no particular reason to change it but, if you do, just make sure to write the same value in the `iptables DNAT` rule (see next section).
     * The are other configuration parameters, documented directly inside `config.py.example`.
 3. Store the emulated SSH server's private keys (`tcp_ssh_rsa` and `tcp_ssh_dss`) you wish to use inside the `secrets/` subdirectory. Similarly, store SSL private key (`tcp_ssl.key`) and certificate (`tcp_ssl_cert.pem`) too. If you do not have existing keys and/or SSL certificates to use, run the following commands to generate new ones:
    <pre>cd secrets/
ssh-keygen -t rsa -f tcp_ssh_rsa -N ""
ssh-keygen -t dsa -f tcp_ssh_dss -N ""
openssl req -new -newkey rsa:1024 -x509 -subj "/C=IT/L=Catania/O=EasyIT/OU=Internal Network/CN=localhost" -days 3650 -nodes -keyout tcp_ssl.key -out tcp_ssl_cert.pem
</pre>
    **Note about SSL**: the previous command will generate a self-signed certificate, which some clients will reject. Also, it is probably a good idea to customize the `Subject Identifier` values.

## Running the honeypot
 1. While not strictly necessary, it is strongly suggested to **use a dedicated IP address for honeypot traffic**, because it will be easier to write `iptables` rules at step 2. You can keep your regular IP address and, at the same time, add a secondary one in NetworkManager (just choose *IPv4 method: manual* and add both primary and secondary addresses).<br/>
    If you do not use NetworkManager, here is how to do add secondary IP address 192.168.1.123 from the command line (however, the following method might conflict with your distribution's network management scripts).
    <pre># ip -4 addr show eth0
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    inet 192.168.1.3/24 brd 192.168.1.255 scope global eth0
       valid_lft forever preferred_lft forever
# **ip -4 addr add 192.168.1.123/24 brd 192.168.1.255 dev eth0**
# ip -4 addr show eth0
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    inet 192.168.1.3/24 brd 192.168.1.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet **192.168.1.123**/24 brd 192.168.1.255 scope global **secondary** eth0
       valid_lft forever preferred_lft forever</pre>
 2. Add the following `iptables` rules: redirect all incoming honeypot TCP traffic to local port 1211
    and discard the remainder of the traffic.
    <pre>iptables -t nat -I PREROUTING -d **192.168.1.123** -p tcp -j DNAT --to-destination :1211
iptables -I INPUT -d **192.168.1.123** ! -p tcp -j DROP</pre>
    **Note 1**: The two listed rules assume that 192.168.1.123 is entirely dedicated to honeypot traffic. If you cannot use such a dedicated IP address, you will have to write more elaborate rules to redirect all incoming TCP connections *except* those you want to be able to contact real locally running sevices; similarly, you will also have to write selective rules to drop all non-TCP traffic *except* packets that your system actually needs (e.g. DNS and DHCP). You will probably also want to add DNS and DHCP servers in the `UDP_DISCARD_FROM` list to avoid polluting the honeypot logs with their UDP packets.<br/>
    **Note 2**: The honeypot only listens on port `1211/tcp`, that is the reason why the first command is needed. It is important to add the `DNAT` rule on the same machine as the honeypot itself, as opposed to the router or the network firewall, because the honeypot relies on `SO_ORIGINAL_DST` to find the original destination port, and it only works for locally-redirected connections.<br/>
    **Note 3**: Unlike TCP, the honeypot intercepts UDP packets through `libpcap` before the firewall kicks in to filter them (see `udp_raw_agent.py`). **It is important to `DROP` (and not `ACCEPT` or `REJECT`) incoming UDP honeypot traffic**, otherwise the OS or the firewall would reply with *Port unreachable* or similar ICMP error packets.
 3. Make sure the `iptables` rules actually work as intended (`wireshark`, `nc IP TCPPORT`, `nc -l TCPPORT`, `nc -u IP UDPPORT` and `nc -u -l UDPPORT` are your friends). The two previously listed rules will work flawlessly on distros that ship with ACCEPT policies and no default firewall rules, such as Ubuntu. Other distros, such as Fedora, come with an extensive set of preloaded `iptables` rules that will almost certainly conflict. In some cases it is easier to rewrite equivalent rules using your distro's favourite `iptables` frontend (e.g. `firewalld` for Fedora).
 4. When you are confident enough, ask your router or network firewall to forward all incoming WAN connections to the honeypot LAN IP address (this feature is usually called *DMZ server* in consumer routers). Of course, this step is not needed if you are configuring the honeypot directly on a WAN-facing machine.
 5. Start the honeypot with `./main.py` as a sudo-enabled user (the `udp_raw_agent.py` component needs to run as root to open some RAW sockets in the beginning, but it will drop privileges immediatly afterwards).<br/>
    **Note**: `udp_raw_agent.py` is started automatically by `main.py`, and `sudo` will be invoked internally. Just run `./main.py` as regular user and you will see the `sudo` password prompt. **Do not** run `sudo ./main.py`, because that would run the whole honeypot as root!

# Protocol support

## SSH and telnet
The honeypot pretends that all SSH and telnet login attempts succeed. Commands are executed by a fake shell that only implements a very basic set of UNIX commands. The fake shell will never access your real system.

## SMTP
The emulated server does not require authentication and it will always accept and log all messages that clients try to send, pretending they were sent or received successfully. SSL-protected SMTP (i.e. the `STARTTLS` command) is supported too.

## HTTP
Two HTTP methods are currently recognized: `GET` and `CONNECT`.
 * `GET` requests are always answered with a standard response and a randomly-generated cookie that is logged and can be used to track responses.
 * `CONNECT` (i.e. proxy) requests will always appear to succeed. Proxied connections are always answered by the honeypot itself and are never forwarded to external servers.

## SIP
The SIP protocol handler detects scan attempts made through the [sipvicious](https://github.com/sandrogauci/sipvicious) scanning tool: `svmap` requests are always replied like a real SIP service would do, and `svwar` scans are always replied so that every tested extension line appears to be available and without any authentication needed. Lastly, attempts to make calls are logged (including the telephone number that the attacker tried to call) and answered with a `501 Not Implemented` response, which aborts the call.

## Netis factory backdoor
The honeypot pretends to be backdoored like some Netis router models. Commands injected through the backdoor are executed inside the same fake shell as SSH and telnet.
