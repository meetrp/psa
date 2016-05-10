# -*- coding: utf-8 -*-

import os
import sys

from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand

import sniffer

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, 'README.md')) as f:
    readme = f.read()

with open(os.path.join(here, 'LICENSE')) as f:
    license = f.read()


class Tox(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        import tox
        errcode = tox.cmdline(self.test_args)
        sys.exit(errcode)


setup(
    name='sniffer',
    version=sniffer.__version__,
    description='Packet sniffer using raw sockets',
    long_description=readme,
    author='Rp',
    author_email='rp@meetrp.com',
    url='https://github.com/meetrp/py.sniffer',
    license=license,
    packages=find_packages(exclude=('tests', 'docs')),
    include_packet_data=True,
    platforms='any',
    tests_require=['tox'],
    cmdclass={'test': Tox},
    test_suite='test.test_sniffer',
    extras_require={
        'testing': ['pytest']
    }
)
