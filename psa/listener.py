"""
.. module:: listener
    :platform: Linux
    :synopsis: A packet listener using raw sockets
"""

import netifaces
import socket
import time


class Listener():
    def __init__(self, iface):
        """
        Initialization of the class
        :param iface: interface on which the packets should be sniffed
        :type iface: str
        """
        if iface is None:
            raise Exception("No network interface provided!")
        self.__iface = iface
        self.__validate_iface()
        self.__soc = None

    def __validate_iface(self):
        """
        Validate if the interface is valid for listening
        :return:
        """
        if self.__iface not in netifaces.interfaces():
            raise Exception("invalid network interface")

    @property
    def ETHER_PACKETS(self):
        return 0x0003

    def connect(self):
        """
        Connect the raw socket on the interface
        :return:
        """
        self.__soc = socket.socket(
                socket.AF_PACKET,
                socket.SOCK_RAW,
                socket.htons(self.ETHER_PACKETS))
        self.__soc.bind((self.__iface, 0))

    def listen(self):
        """
        Start listening
        :return:
        """
        while True:
            buf, _ = self.__soc.recvfrom(4096)
            print(time.time(), len(buf))
