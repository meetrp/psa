"""
.. module:: sniffer
    :platform: Linux
    :synopsis: A packet sniffer using raw sockets
"""


class Sniffer():
    def __init__(self, dev="eth0"):
        """
        Initialization of the class
        :param dev: interface on which the packets should be sniffed
        :type dev: str
        """
        self.__dev = dev

    def get_dev(self):
        """
        Returns the device on which sniffer is listening
        :return:
        """
        return self.__dev
