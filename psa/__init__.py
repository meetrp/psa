"""
psa is a network packet listner, analyzer & logger using raw socket.
    * The *psa* will listen for all ethernet packets
    * The *analyzer* will parse the packet & pick the necessary details (like
      IP, port, protocol, etc..)
    * The *logger* will log them either to the screen or to a file via the CSV
      format
"""

__version__ = '0.1'
