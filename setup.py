# -*- coding: utf-8 -*-

import os
import sys

from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand

import psa

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
    name='psa',
    version=psa.__version__,
    description='Packet listener, parser & analyzer using raw sockets',
    long_description=readme,
    author='Rp',
    author_email='rp@meetrp.com',
    url='https://github.com/meetrp/psa',
    license=license,
    packages=find_packages(exclude=('tests', 'docs')),
    include_packet_data=True,
    platforms='any',
    setup_requires=["pytest-runner"],
    tests_require=['pytest'],
    cmdclass={'test': Tox},
    test_suite='pytest',
    install_requires=[
        'netifaces',
    ],
    extras_require={
        'testing': ['pytest']
    },
)
