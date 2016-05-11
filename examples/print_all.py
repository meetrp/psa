"""
This function will print all the details of all packets
"""

from sniffer import sniffer

s = sniffer.Sniffer()
print s.get_dev()
