#!/usr/bin/python

#
# Copyright 2013 Rp (www.meetrp.com)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#       http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#
# Ability to sniff into all packets & track what sites are being contacted
# and when.
# 
# courtesy:
#	http://www.binarytides.com/python-packet-sniffer-code-linux/
#	http://stackoverflow.com/questions/24415294/python-arp-sniffing-raw-socket-no-reply-packets
#	http://www.pythonforpentesting.com/2014/09/packet-injection-capturing-response.html
#	http://repo.hackerzvoice.net/depot_madchat/ebooks/TCP-IP_Illustrated/dns_the.htm
#	http://www.firewall.cx/networking-topics/protocols/domain-name-system-dns/161-protocols-dns-response.html
#

###
# All required imports
from os import path, popen
from socket import AF_INET, SOCK_DGRAM, AF_INET6, AF_PACKET, SOCK_RAW
from socket import socket, inet_ntoa, inet_ntop, ntohs
from struct import unpack, pack
from sys import argv, exit
from time import gmtime, strftime, time

# FIXME: Remove the dependencies on Redis
from redis import Redis

# TODO: Move these to a constants file
###
# Packet type
ARP_ID = "0x806"		# ARP Packet
IPv4_ID = "0x800"		# IPv4 Packet
IPv6_ID = "0x86DD"		# IPv6 Packet

###
# Header len
ETH_HDR_LEN = 14
ARP_HDR_LEN = 28
IPv4_HDR_LEN = 20
IPv6_HDR_LEN = 40
TCP_HDR_LEN = 20
UDP_HDR_LEN = 8

###
# Specific to Ethernet Packets
ETH_UNPACK_PATTERN='!6s6sH'
ETH_TYPE_POS = 2

###
# Specific to ARP Packets
ARP_UNPACK_PATTERN = '2s2s1s1s2s6s4s6s4s'
ARP_SRC_ADDR_POS = 6			# Where the source address is stored
ARP_DEST_ADDR_POS = 8			# Where the destination address is stored

###
# Specific to IPv4 Packets
IPv4_UNPACK_PATTERN = '!BBHHHBBH4s4s'
IPv4_PROTOCOL_POS = 6			# Where the protocol info is stored
IPv4_SRC_ADDR_POS = 8			# Where the source address is stored
IPv4_DEST_ADDR_POS = 9			# Where the dest address is stored
IPv4_ICMP_PROTO = 1			# ICMP Protocol
IPv4_TCP_PROTO = 6			# TCP Protocol
IPv4_UDP_PROTO = 17			# UDP Protocol

###
# Specific to IPv6 Packets
IPv6_UNPACK_PATTERN = '!4sHBB16s16s'
IPv6_PROTOCOL_POS = 3			# Where the protocol info is stored
IPv6_SRC_ADDR_POS = 4			# Where the source address is stored
IPv6_DEST_ADDR_POS = 5			# Where the dest address is stored
IPv6_ICMP_PROTO = 58			# ICMP Protocol
IPv6_TCP_PROTO = 6			# TCP Protocol
IPv6_UDP_PROTO = 17			# UDP Protocol

###
# Specific to UDP Packets
UDP_UNPACK_PATTERN = '!HHHH'
UDP_SRC_PORT_POS = 0			# Where the source port is stored
UDP_DEST_PORT_POS = 1			# Where the destination port is stored

###
# Specific to TCP Packets
TCP_UNPACK_PATTERN = '!HHLLBBHHH'
TCP_SRC_PORT_POS = 0			# Where the source port is stored
TCP_DEST_PORT_POS = 1			# Where the destination port is stored

###
# Ports of interest
DNS_PORT = "53"

###
# Specific to DNS packet
DNS_UNPACK_PATTERN = '!HHHHHH'
DNS_HDR_LEN = 12
DNS_ANS_UNPACK_PATTERN = '!HHHIH'
DNS_ANS_HDR_LEN = 12
DNS_IPv4_UNPACK_PATTERN = '!4s'
DNS_IPv4_SIZE = 4			# 4 Bytes to store an IP
DNS_FLAGS_POS = 1
DNS_NUM_ANS_POS = 3
DNS_ANS_TYPE_POS = 1
DNS_ANS_CLASS_POS = 2
DNS_QUERY_TYPE_POS = 0
DNS_QUERY_CLASS_POS = 1

###
# Values of interest in DNS packet
DNS_RESP = "0x8180"		# Standard Query response, No Error
DNS_A_TYPE = "1"		# IP Address
DNS_CNAME_TYPE = "5"		# Canonical name
DNS_CLASS = "1"			# Internet Address
DNS_NAME_END = 0		# Default end value for names
DNS_PTR_END = 192		# Default end value for PTR types used in names
DNS_MAX_NAME_LEN = 63		# Max length of Names in DNS packets
DNS_PTR_SIZE = 2		# 2 Bytes

###
# Pretty print hard-coded values
DATE_LEN = 14
TYPE_LEN = 12
IP_LEN = 26
MAC_LEN = 18
PORT_LEN = 6


###
# Default values
DEFAULT_NETWORK_INTERFACE = "eth0"
DEFAULT_PROC_ROUTE_PATH = "/proc/net/route"
DEFAULT_NMCLI_COMMAND = "nmcli dev list iface "
DEFAULT_NMCLI_DNS_LOOKUP = "DNS"
DEFAULT_NMCLI_DNS_POS = "2"
DEFAULT_NMCLI_DHCP_LOOKUP = "dhcp_ser"
DEFAULT_NMCLI_DHCP_POS = "4"
DEFAULT_REDIS_SERVER = "localhost"
DEFAULT_EXPIRE_TIME = 86400		# Expires after 24 hours to save space

###
# global values
g_local_MAC = ""
g_print_mac = False
g_print_in_csv = False
g_print_human_readable = False
g_cache_server = None

###
# Do Not Print info about this
#g_disallowed_ip = set([str(local_ip), "127.0.0.1", "123.123.123.123"])
#g_disallowed_port = set([137, 1900, 80, 443, 53])
g_disallowed_ip = set()
g_disallowed_port = set()


###
# populate all known ports
ports=dict()
with open("./known.ports") as ports_file:
	for line in ports_file:
		if line[0] not in "/\n":
			_blah = line.strip().split(',')
			ports[_blah[0]] = _blah[1]

###
# populate all known ether types
ethertypes=dict()
with open("./ether.types") as types_file:
	for line in types_file:
		if line[0] not in "/\n":
			_blah = line.strip().split(',')
			ethertypes[_blah[0]] = _blah[1]

###
# get sys path for a network device
#
def get_sys_path(net_iface_dev):
	return '/sys/class/net/' + net_iface_dev + '/address'

###
# initialize cache
#
def init_cache():
	global g_cache_server
	g_cache_server = Redis(DEFAULT_REDIS_SERVER)


###
# Cache Set
#
def cache_set(ip_array, url):
	if not g_cache_server: return
	for ip in ip_array: g_cache_server.setex(ip, url, DEFAULT_EXPIRE_TIME)


###
# Cache Get
#
def cache_get(ip):
	if not g_cache_server: return None
	return g_cache_server.get(ip)


###
# Read the default gateway directly from /proc."""
#
def get_default_route(net_iface_dev):
	with open(DEFAULT_PROC_ROUTE_PATH) as fh:
		for line in fh:
			fields = line.strip().split()
			if fields[0] != net_iface_dev:
				continue
			if (fields[1] != '00000000') or \
					not int(fields[3], 16) & 2:
				continue
			ip = inet_ntoa(pack("<L", int(fields[2], 16)))
			cache_set([ip], "Default-Route")


###
# Retrieve the DNS servers used
#
def get_DNS_servers(net_iface_dev):
	_blah = popen(DEFAULT_NMCLI_COMMAND + net_iface_dev + \
			" | grep " + DEFAULT_NMCLI_DNS_LOOKUP + \
			" | awk '{print $" + DEFAULT_NMCLI_DNS_POS + \
			"}'").readlines()
	if not _blah: return []

	namify=["Primary-DNS", "Secondary-DNS", "Tertiary-DNS"]
	servers = [x.strip() for x in _blah]
	for dns in servers:
		cache_set([dns], namify[servers.index(dns)])


###
# Retrieve the DHCP servers used
#
def get_DHCP_server(net_iface_dev):
	_blah = popen(DEFAULT_NMCLI_COMMAND + net_iface_dev + \
			" | grep " + DEFAULT_NMCLI_DHCP_LOOKUP + \
			" | awk '{print $" + DEFAULT_NMCLI_DHCP_POS + \
			"}'").readlines()
	if not _blah: return []

	namify=["Primary-DHCP", "Secondary-DHCP", "Tertiary-DHCP"]
	servers = [x.strip() for x in _blah]
	for dhcp in servers:
		cache_set([dhcp], namify[servers.index(dhcp)])

###
# Retrieve the local IP
#
def local_ip():
	ip = ([(s.connect(('8.8.8.8', 80)), s.getsockname()[0], s.close()) \
			for s in [socket(AF_INET, SOCK_DGRAM)]][0][1])
	cache_set([ip], "Local-IP")


###
# Retrieve the current MAC
#
def local_MAC(sys_path):
	with open(sys_path) as sys_file:
		for line in sys_file:
			if line[0] not in "/\n":
				return line.strip()


###
# Format the MAC address into human readable form
#
def fmt_MAC(pkt):
	return "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % \
		(ord(pkt[0]) , ord(pkt[1]) , ord(pkt[2]), \
		ord(pkt[3]), ord(pkt[4]) , ord(pkt[5]))


###
# Format the IP address into human readable form
#
def fmt_IP(pkt):
	return "%d.%d.%d.%d" % \
		(ord(pkt[0]) , ord(pkt[1]) , ord(pkt[2]), ord(pkt[3]))


###
# Convert IP to Name
#
def MAC_to_name(mac):
	if not g_print_human_readable: return mac

	if ( mac == g_local_MAC.upper() ):
		return "Local-MAC"
	else:
		return mac


###
# Convert IP to Name
#
def ip_to_name(ip):
	if not g_print_human_readable: return ip
	return ip if not cache_get(ip) else cache_get(ip)


###
# Is the dest address & port acceptable
#
def is_acceptable_dest(dest_addr, dest_port):
	if dest_addr in g_disallowed_ip: return False
	elif int(dest_port) in g_disallowed_port: return False
	else: return True

###
# Prettify the print in a tablular column
#
def pretty_print(etype, etype_transport,
		src_mac, src_addr, src_port,
		dest_mac, dest_addr, dest_port):
	cur_time = strftime("%Y-%m-%d %H:%M:%S", gmtime())

	if etype_transport != "": etype += "/" + etype_transport

	if g_print_human_readable \
		and (dest_port in ports):
		dest_port = ports[dest_port] + "(" + dest_port + ")"

	if g_print_human_readable \
		and (src_port in ports):
		src_port = ports[src_port] + "(" + src_port + ")"

	# generic data
	data = '| ' + "%.20s" % cur_time.ljust(DATE_LEN)
	data += '\t| ' + "%.12s" % etype.ljust(TYPE_LEN) 

	# source data
	data += '\t| ' + "%.26s" % ip_to_name(src_addr).rjust(IP_LEN)
	if g_print_mac:
		data += '(' + MAC_to_name(src_mac.upper()).rjust(MAC_LEN) + ')'
	data += ' | ' + "%.8s" % src_port.ljust(PORT_LEN)

	# destination data
	data += '\t| ' + "%.26s" % ip_to_name(dest_addr).rjust(IP_LEN)
	if g_print_mac:
		data += '(' + MAC_to_name(dest_mac.upper()).rjust(MAC_LEN) + ')'
	data += ' | ' + dest_port

	print data


###
# Print in CSV format
#
def print_csv(etype, etype_transport,
		src_mac, src_addr, src_port,
		dest_mac, dest_addr, dest_port):
	cur_time = time()

	# generic data
	data = str(cur_time)
	data += ',' + etype
	data += ',' + etype_transport

	# source data
	data += ',' + ip_to_name(src_addr)
	if g_print_mac: data += ',' + MAC_to_name(src_mac.upper())
	if g_print_human_readable:
		if (src_port in ports): data += ',' + ports[src_port]
		else: data += ','
	data += ',' + src_port

	# destination data
	data += ',' + ip_to_name(dest_addr)
	if g_print_mac: data += ',' + MAC_to_name(dest_mac.upper())
	if g_print_human_readable:
		if (dest_port in ports): data += ',' + ports[dest_port]
		else: data += ','
	data += ',' + dest_port

	print data


###
# Print the final data
#
def g_print_data(etype, etype_transport,
		src_mac, src_addr, src_port,
		dest_mac, dest_addr, dest_port):
	if not is_acceptable_dest(dest_addr, dest_port):
		return

	if g_print_human_readable and (etype in ethertypes):
		etype = ethertypes[etype]

	if g_print_human_readable and dest_port == "0": dest_port = "n/a"
	if g_print_human_readable and src_port == "0": src_port = "n/a"

	if g_print_in_csv:
		print_csv(etype, etype_transport, 		\
				src_mac, src_addr, src_port, 	\
				dest_mac, dest_addr, dest_port)
	else:
		pretty_print(etype, etype_transport, 		\
				src_mac, src_addr, src_port, 	\
				dest_mac, dest_addr, dest_port)



###
# Dump information from TCP package
#
# =============> TCP Header <===============
#
#    0         7            15           23            31    OCTET
#    ---------------------------------------------------
#    |    Source Port        |    Destination Port     |        0
#    ---------------------------------------------------
#    |                Sequence Number                  |        4
#    ---------------------------------------------------
#    |            Acknowledgement Number               |        8
#    ---------------------------------------------------
#    |    Offset |U|A|P|R|S|F|       Window            |        12
#    ---------------------------------------------------
#    |    Check sum        |         Urgent Pointer    |        16
#    ---------------------------------------------------
#    |            Options and Padding                  |        20
#    ---------------------------------------------------
#
# Courtesy: http://ptgmedia.pearsoncmg.com/images/chap3_0672323516/elementLinks/03table01.gif
#
def retrieve_tcp_packet_info(packet, isIPv6 = False):
	start_pos = ETH_HDR_LEN + IPv4_HDR_LEN
	if isIPv6:
		start_pos = ETH_HDR_LEN + IPv6_HDR_LEN

	tcp_header = unpack(TCP_UNPACK_PATTERN, \
				packet[start_pos:start_pos + TCP_HDR_LEN])
	src_port = str(tcp_header[TCP_SRC_PORT_POS])
	dest_port = str(tcp_header[TCP_DEST_PORT_POS])

	return src_port, dest_port


###
# Dump information from UDP package
#
# =============> UDP Header <===============
#
#    0         7            15           23            31    OCTET
#    ---------------------------------------------------
#    |    Source Port        |     estination Port     |        0
#    ---------------------------------------------------
#    |        Length         |        Checksum         |        4
#    ---------------------------------------------------
#    |                     Data                        |        8
#    ---------------------------------------------------
#
# Courtesy: http://en.wikipedia.org/wiki/User_Datagram_Protocol
#
def retrieve_udp_packet_info(packet, isIPv6=False):
	start_pos = ETH_HDR_LEN + IPv4_HDR_LEN
	if isIPv6:
		start_pos = ETH_HDR_LEN + IPv6_HDR_LEN

	udp_header = unpack(UDP_UNPACK_PATTERN, \
				packet[start_pos:start_pos + UDP_HDR_LEN])
	src_port = str(udp_header[UDP_SRC_PORT_POS])
	dest_port = str(udp_header[UDP_DEST_PORT_POS])

	return src_port, dest_port


###
# Retrieve the NAME (domain, typically) from the DNS packet
#
# ===========> Name Representation <=============
#
# For example, if the name is 'tech.meetrp.com'
# 	-----------------------------------
# 	|4|t|e|c|h|6|m|e|e|t|r|p|3|c|o|m|0|
# 	-----------------------------------
# Each name begins with a 1-byte count that specifies the
# number of bytes that follow. That name is terminated with
# a byte of 0. Each count byte must be in the range of 0 to
# 63.
#
# Courtesy: http://repo.hackerzvoice.net/depot_madchat/ebooks/TCP-IP_Illustrated/dns_the.htm
#
def decode_name_from_dns_packet(start_pos, packet, isPtr=False):
	name = ""

	# As part of message compression, pointers are used to reference
	# to part of the previously filled domain name. These are used
	# only in the response section. So, if Query is sent for:
	# www.github.com and the CNAME is github.com the a pointer is
	# used inside the RR section to point the part of the packet
	# where 'github.com' already appears. Now in these scenarios
	# the end of name is, necesarily, 'zero' but '0xC0' (i.e. 192)
	prev_pos = start_pos
	(next_len,) = unpack('!B', packet[prev_pos:prev_pos+1])
	prev_pos += 1
	while ((next_len != DNS_NAME_END) and (next_len != DNS_PTR_END)):
		if name: name += "."
		name += packet[prev_pos:prev_pos+next_len]
		prev_pos += next_len
		(next_len,) = unpack('!B', packet[prev_pos:prev_pos+1])
		prev_pos += 1

	# if a PTR was used the increment by one because a pointer is
	# of 16-bit in length (i.e., 2 Bytes).
	if (next_len == DNS_PTR_END): prev_pos += 1

	return name, prev_pos


###
# Is the type a 'Host Address' & class the 'Internet Address'
#
def is_type_and_class_valid(dns_type, dns_class):
	return ((str(int(dns_type)) == DNS_A_TYPE) and \
		(str(int(dns_class)) == DNS_CLASS))


###
# Parse a DNS Response & cache the mapping for reverse mapping
#
# =============> DNS Header <===============
#
#    0         7            15           23            31    OCTET
#    ---------------------------------------------------
#    |    Identification    |         Flags            |        0
#    ---------------------------------------------------
#    |    No. of Questions  |    No. of Answers        |        4
#    ---------------------------------------------------
#    |    No. of Authority  |     No. of Additional    |        8
#    ---------------------------------------------------
#    |                    Questions                    |    variable size
#    ---------------------------------------------------
#    |                    Answers                      |    variable size
#    ---------------------------------------------------
#    |                    Authority                    |    variable size
#    ---------------------------------------------------
#    |                Additional Info                  |    variable size
#    ---------------------------------------------------
#
# Courtesy:
#	http://repo.hackerzvoice.net/depot_madchat/ebooks/TCP-IP_Illustrated/dns_the.htm
#	http://www.firewall.cx/networking-topics/protocols/domain-name-system-dns/161-protocols-dns-response.html
#
def parse_and_cache_dns_response(packet, isIPv6=False):
	start_pos = ETH_HDR_LEN + IPv4_HDR_LEN + UDP_HDR_LEN
	if isIPv6:
		start_pos = ETH_HDR_LEN + IPv6_HDR_LEN + UDP_HDR_LEN

	end_pos = start_pos + DNS_HDR_LEN

	dns_header = unpack(DNS_UNPACK_PATTERN, packet[start_pos:end_pos])
	flags = str(hex(dns_header[DNS_FLAGS_POS]))
	if flags != DNS_RESP:
		return

	number_of_answers = int(dns_header[DNS_NUM_ANS_POS])

	# Retrieve the Question field the DNS packet
	url, next_pos = decode_name_from_dns_packet(end_pos, packet)

	# '4' bytes for "DNS Type" & "DNS Class" data
	answer_pos = next_pos+4
	query_details = unpack('!HH', packet[next_pos:answer_pos])
	if is_type_and_class_valid(query_details[DNS_QUERY_TYPE_POS], \
					query_details[DNS_QUERY_CLASS_POS]):
		ip_array = []
		while number_of_answers:
			answer_data = unpack(DNS_ANS_UNPACK_PATTERN, \
						packet[answer_pos:answer_pos+DNS_ANS_HDR_LEN])
			answer_pos += DNS_ANS_HDR_LEN

			# Is this a valid class
			if (str(int(answer_data[DNS_ANS_CLASS_POS])) != DNS_CLASS):
				print "Some error while processing for", url, \
					" class data:", \
					str(int(answer_data[DNS_ANS_CLAS_POS]))
				exit(1)

			# Is this a 'CNAME' record
			if (str(int(answer_data[DNS_ANS_TYPE_POS])) == DNS_CNAME_TYPE):
				# Unused
				#ptr = str(hex(answer_data[0]))		# Pointer to Doman Name Name
				#ttl = str(hex(answer_data[3]))		# TTL??!
				#d_len = str(int(answer_data[4]))	# Data Length

				(length,) = unpack('!B', \
							packet[answer_pos:answer_pos+1])
				if length > DNS_MAX_NAME_LEN: # PTR type
					answer_pos += DNS_PTR_SIZE
				else: # name decoded
					(length,) =
						unpack('!B', \
						packet[answer_pos:answer_pos+1])
					alias_name, answer_pos = decode_name_from_dns_packet(answer_pos, packet, True)

			# Is this a 'A' record
			if (str(int(answer_data[DNS_ANS_TYPE_POS])) == \
					DNS_A_TYPE):
				# Unused
				#ptr = str(hex(answer_data[0]))		# Pointer to Doman Name Name
				#ttl = str(hex(answer_data[3]))		# TTL??!
				#d_len = str(int(answer_data[4]))	# Data Length

				(ip_str,) = unpack(DNS_IPv4_UNPACK_PATTERN, \
							packet[answer_pos:answer_pos+DNS_IPv4_SIZE])
				ip_array.append(fmt_IP(ip_str))
				answer_pos += DNS_IPv4_SIZE

			number_of_answers -= 1
	
		cache_set(ip_array, url)
		

###
# Dump information from IPv4 package
#
# =============> IPv4 Header <===============
#
#    0     3     7              15          23            31    OCTET
#    ------------------------------------------------------
#    | Ver | Hdr |    Type of    |        Total           |        0
#    |     | Len |    Service    |        Length          |
#    ------------------------------------------------------
#    |    Identification         | Flags |    Offset      |        4
#    ------------------------------------------------------
#    |    TTL    |    Protocol   |         CheckSum       |        8
#    ------------------------------------------------------
#    |                    Source Address                  |        12
#    ------------------------------------------------------
#    |                Destination Address                 |        16
#    ------------------------------------------------------
#    |            IP Options                |    Padding  |        20
#    ------------------------------------------------------
#    |                     Data                           |        24
#    ------------------------------------------------------
#    |                    More Data                       |        28
#    -------------------------------------------------------
#
# Courtesy: http://www.yaldex.com/tcp_ip/FILES/04fig03.gif
#
def retrieve_ipv4_packet_info(packet):
	ip_header = unpack(IPv4_UNPACK_PATTERN, \
				packet[ETH_HDR_LEN:ETH_HDR_LEN + IPv4_HDR_LEN])

	src_addr = str(inet_ntoa(ip_header[IPv4_SRC_ADDR_POS]))
	dest_addr = str(inet_ntoa(ip_header[IPv4_DEST_ADDR_POS]))

	protocol = ip_header[IPv4_PROTOCOL_POS]
	transport_type = str(protocol)
	if protocol == IPv4_TCP_PROTO:
		src_port, dest_port = retrieve_tcp_packet_info(packet)
		if g_print_human_readable: transport_type = "TCP"
	elif protocol == IPv4_UDP_PROTO:
		src_port, dest_port = retrieve_udp_packet_info(packet)
		if g_print_human_readable: transport_type = "UDP"
		if src_port == DNS_PORT: #DNS Response
			parse_and_cache_dns_response(packet)
	elif protocol == IPv4_ICMP_PROTO:
		src_port, dest_port = "0", "0"
		if g_print_human_readable: transport_type = "ICMP"
	else:
		#transport_type = "**"+str(protocol)
		src_port, dest_port = "0", "0"

	return transport_type, src_addr, src_port, dest_addr, dest_port


###
# Dump information from IPv6 package
#
# =============> IPv6 Header <===============
#
#    0     3     7            15            23             31    OCTET
#    ------------------------------------------------------
#    | VER |    Class    |            Flow Label          |        0
#    ------------------------------------------------------
#    |     Payload Length     | Protocol |   Hop Limit    |        4
#    ------------------------------------------------------
#    |                Source Address                      |        8
#    ------------------------------------------------------
#    |                Source Address (cont)               |        12
#    ------------------------------------------------------
#    |                Source Address (cont)               |        16
#    ------------------------------------------------------
#    |                Source Address (cont)               |        20
#    ------------------------------------------------------
#    |            Destination Address                     |        24
#    ------------------------------------------------------
#    |            Destination Address (cont)              |        28
#    ------------------------------------------------------
#    |            Destination Address (cont)              |        32
#    ------------------------------------------------------
#    |            Destination Address (cont)              |        36
#    ------------------------------------------------------
#
# Courtesy: http://www.tutorialspoint.com/ipv6/images/IPv6_header.jpg
#
def retrieve_ipv6_packet_info(packet):
	ip_header = unpack(IPv6_UNPACK_PATTERN, \
				packet[ETH_HDR_LEN:ETH_HDR_LEN + IPv6_HDR_LEN])

	src_addr = str(inet_ntop(AF_INET6, ip_header[IPv6_SRC_ADDR_POS]))
	dest_addr = str(inet_ntop(AF_INET6, ip_header[IPv6_DEST_ADDR_POS]))

	protocol = ip_header[IPv6_PROTOCOL_POS]
	transport_type = str(protocol)
	if protocol == IPv6_TCP_PROTO:
		src_port, dest_port = retrieve_tcp_packet_info(packet, True)
		if g_print_human_readable: transport_type = "TCP"
	elif protocol == IPv6_UDP_PROTO:
		src_port, dest_port = retrieve_udp_packet_info(packet, True)
		if g_print_human_readable: transport_type = "UDP"
	elif protocol == IPv6_ICMP_PROTO:
		src_port, dest_port = "0", "0"
		if g_print_human_readable: transport_type = "ICMP"
	else:
		#transport_type = "**"+str(protocol)
		src_port, dest_port = "0", "0"

	return transport_type, src_addr, src_port, dest_addr, dest_port

###
# Dump information from ARP package
#
# =============> ARP Header <===============
#
#    0         7            15                         31     OCTET
#    ---------------------------------------------------
#    |    Hardware Type     |        Protocol Type     |        0
#    ---------------------------------------------------
#    | H/w Len |  Proto Len |            OpCode        |        4
#    ---------------------------------------------------
#    |            Source MAC Address                   |        8
#    ---------------------------------------------------
#    |         Source Protocol Address                 |        12
#    ---------------------------------------------------
#    |        Destination MAC Address                  |        16
#    ---------------------------------------------------
#    |        Destination Protocol Address             |        20
#    ---------------------------------------------------
#
# Courtesy: https://reaper81.files.wordpress.com/2010/07/arp-header1.png
#
def retrieve_arp_packet_info(packet):
	arp_header = unpack(ARP_UNPACK_PATTERN, \
				packet[ETH_HDR_LEN:ETH_HDR_LEN+ARP_HDR_LEN])

	src_addr = str(inet_ntoa(arp_header[ARP_SRC_ADDR_POS]))
	dest_addr = str(inet_ntoa(arp_header[ARP_DEST_ADDR_POS]))

	dest_port = "0"
	src_port = "0"

	return src_addr, src_port, dest_addr, dest_port


###
# Retreive all the required infromation from an ethernet
# packet
#
# =============> Eth Header <===============
#
#    0         7            15           23            31    OCTET
#    ---------------------------------------------------
#    |         Destination MAC Address (first 32 bits) |        0
#    ---------------------------------------------------
#    | Dest MAC (last 16b)    |Source MAC Address (16b)|        4
#    ---------------------------------------------------
#    |            Source MAC Address (last 32 bits)    |        8
#    ---------------------------------------------------
#    | Ethernet Type Code    | Data starts from here.. |        12
#    ---------------------------------------------------
#    |                     Data                        |        16
#    ---------------------------------------------------
#
# courtesy: http://ipv6.com/images/diagrams/tcp5.gif
#
def retrieve_eth_packet_info(packet):
	eth_header = packet[:ETH_HDR_LEN]
	eth = unpack(ETH_UNPACK_PATTERN, eth_header)
	etype = '0x' + str(hex(eth[ETH_TYPE_POS])[ETH_TYPE_POS:]).upper()

	# retreive MAC from eth packets
	dest_mac = fmt_MAC(packet[0:6])
	src_mac = fmt_MAC(packet[6:12])

	return etype, src_mac, dest_mac


###
# Dump information from the package
#
def dump_packet_info(packet):
	etype, src_mac, dest_mac = retrieve_eth_packet_info(packet)

	etype_transport = ""
	if etype == ARP_ID:	# ARP Packet
		src_addr, src_port, \
			dest_addr, dest_port = retrieve_arp_packet_info(packet)
	elif etype == IPv4_ID:	# IPv4 Packet
		etype_transport, src_addr, src_port, \
			dest_addr, dest_port = retrieve_ipv4_packet_info(packet)
	elif etype == IPv6_ID:	# IPv6 Packet
		etype_transport, src_addr, src_port, \
			dest_addr, dest_port = retrieve_ipv6_packet_info(packet)
	else:
		print "------ ", etype, 				\
			MAC_to_name(src_mac), MAC_to_name(dest_mac), 	\
			"------ "
		return

	g_print_data(etype, etype_transport, \
			src_mac, src_addr, src_port, \
			dest_mac, dest_addr, dest_port)


###
# print headers for pretty print
#
def print_hdrs():
	hdr_date = "DATE/TIME"
	hdr_type = "TYPE"
	hdr_src_ip = "SOURCE IP"
	hdr_dest_ip = "DEST IP"
	hdr_src_port = "PORT"
	hdr_dest_port = "PROTOCOL(PORT)"
	hdr_src_mac = "SOURCE MAC"
	hdr_dest_mac = "DEST MAC"

	print "-------------------------------------------------------------------------------------------------------------------------------------------"
	hdr = '| ' + hdr_date.ljust(DATE_LEN)
	hdr += '\t| ' + hdr_type.ljust(TYPE_LEN)
	hdr += '\t| ' + hdr_src_ip.rjust(IP_LEN)
	if g_print_mac: hdr += '(' + hdr_src_mac.rjust(MAC_LEN) + ')'
	hdr += ' | ' + hdr_src_port.ljust(PORT_LEN)
	hdr += '\t| ' + hdr_dest_ip.rjust(IP_LEN)
	if g_print_mac: hdr += '(' + hdr_dest_mac.rjust(MAC_LEN) + ')'
	hdr += ' | ' + hdr_dest_port

	print hdr

	print "-------------------------------------------------------------------------------------------------------------------------------------------"


###
# print headers for pretty print
#
def print_csv_hdrs():
	hdr_date = "timestamp"
	hdr_type = "type"
	hdr_transport = "transport"
	hdr_src_ip = "srcip"
	hdr_dest_ip = "destip"
	hdr_src_port = "srcport"
	hdr_src_proto = "srcprotocol"
	hdr_dest_port = "destport"
	hdr_dest_proto = "destprotocol"
	hdr_src_mac = "srcmac"
	hdr_dest_mac = "destmac"

	hdr = hdr_date
	hdr += ',' + hdr_type
	hdr += ',' + hdr_transport
	hdr += ',' + hdr_src_ip
	if g_print_mac: hdr += ',' + hdr_src_mac
	if g_print_human_readable: hdr += ',' + hdr_src_proto
	hdr += ',' + hdr_src_port
	hdr += ',' + hdr_dest_ip
	if g_print_mac: hdr += ',' + hdr_dest_mac
	if g_print_human_readable: hdr += ',' + hdr_dest_proto
	hdr += ',' + hdr_dest_port
	print hdr


###
# The main functionlity starts here
#
def start(net_iface_dev):
	print
	print "====================================|  SNIFFing on",net_iface_dev," |===================================="
	print

	# Both incoming & outgoing ETH packets
	s=socket(AF_PACKET, SOCK_RAW, ntohs(0x0003))
	s.bind((net_iface_dev, 0))

	if g_print_in_csv:
		print_csv_hdrs()
	else:
		print_hdrs()

	while True:
		buf = s.recvfrom(4096)
		dump_packet_info(buf[0])


###
# Main()
#
def main():
	# get IFace from the command prompt
	net_iface_dev = DEFAULT_NETWORK_INTERFACE
	if len(argv) == 2:
		net_iface_dev = argv[1]

	if not path.isfile(get_sys_path(net_iface_dev)):
		print "Network Interface \"" + net_iface_dev + \
			"\" is not available!"
		return False
	else:
		init_cache()

		# Populate the static values
		local_ip()
		get_default_route(net_iface_dev)
		get_DNS_servers(net_iface_dev)
		get_DHCP_server(net_iface_dev)

		# global values
		global g_local_MAC, g_print_mac, g_print_in_csv,
			g_print_human_readable
		g_local_MAC = local_MAC(get_sys_path(net_iface_dev))
		g_print_mac = False
		g_print_in_csv = False
		g_print_human_readable = True

		start(net_iface_dev)


if __name__ == "__main__":
	exit(main())
