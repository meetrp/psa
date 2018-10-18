[![Build Status](https://travis-ci.org/meetrp/psa.svg?branch=develop)](https://travis-ci.org/meetrp/psa)
[![Coverage Status](https://coveralls.io/repos/github/meetrp/psa/badge.svg?branch=develop)](https://coveralls.io/github/meetrp/psa?branch=develop)
[![HitCount](http://hits.dwyl.io/meetrp/psa.svg)](http://hits.dwyl.io/meetrp/psa)
[![PEP8](https://img.shields.io/badge/code%20style-pep8-orange.svg)](https://www.python.org/dev/peps/pep-0008/)

sniffer.py
==========
Network sniffer. The scope is to **Sniff every incoming as well as outgoing packet.** Then parse various packets like 'Ethernet', 'IP', 'TCP/UDP' &amp; 'DNS' to log the network activity.

Features
========
This started as a method for me to monitor network activity on my laptop even while idle. So the feature-set is as per my requirement:
* Human readable protocol types like TCP, UDP, etc...
* Human readable packet types like IPv4, ARP, IPv6, etc...
* Human readbale port numbers like DNS, HTTP, HTTPS, etc...
* Human readable IPs like Local-IP, PRIMARY-DNS, etc...
* Reverse IP to domain mapping so the IPs will given a domain name like "google.com" or "dropbox.com"
* Both pretty-print or print in csv format is possible.

Example usage
=============
	$> sudo python ./sniffer.py eth0
	
	====================================|  SNIFFing on eth0  |====================================
	
	-------------------------------------------------------------------------------------------------------------------------------------------
	| DATE/TIME     	    | TYPE        	|                  SOURCE IP | PORT  	|                    DEST IP | PROTOCOL(PORT)
	-------------------------------------------------------------------------------------------------------------------------------------------
	| 2014-10-10 03:29:59	| IPv4/UDP    	|                   Local-IP | 33372 	|                Primary-DNS | DNS(53)
	| 2014-10-10 03:29:59	| IPv4/UDP    	|                Primary-DNS | DNS(53)	|                   Local-IP | 33372
	| 2014-10-10 03:30:04	| ARP         	|                   Local-IP | n/a   	|                Primary-DNS | n/a
	| 2014-10-10 03:30:04	| ARP         	|                Primary-DNS | n/a   	|                   Local-IP | n/a
	| 2014-10-10 03:30:08	| IPv4/UDP    	|                   Local-IP | Dropbox 	|            255.255.255.255 | Dropbox LanSync Protocol(17500)
	| 2014-10-10 03:30:08	| IPv4/UDP    	|                   Local-IP | Dropbox 	|             192.168.81.255 | Dropbox LanSync Protocol(17500)
	| 2014-10-10 03:30:15	| IPv4/TCP    	|        notify9.dropbox.com | HTTP(80)	|                   Local-IP | 40208
	| 2014-10-10 03:30:15	| IPv4/TCP    	|                   Local-IP | 40208 	|        notify9.dropbox.com | HTTP(80)

