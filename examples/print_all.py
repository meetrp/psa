"""
This function will print all the details of all packets
"""

from psa import listener

CONFIG = {
        'iface': 'eth0'
}


s = listener.Listener(CONFIG["iface"])
s.connect()
s.listen()
