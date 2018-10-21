"""
Test the main listener package
"""

import netifaces
import pytest
import socket
from .context import listener

VALID_TEST_OBJ = {
        "interfaces": netifaces.interfaces()
        }

ALL_TEST_OBJ = {
        "interfaces":
        [
            pytest.param(
                None,
                marks=pytest.mark.xfail(raises=Exception, strict=True))
        ]
        + [
            pytest.param(
                "dummy_dev0",
                marks=pytest.mark.xfail(strict=True))
        ]
        + VALID_TEST_OBJ["interfaces"]
        }


@pytest.fixture
def listener_obj(request):
    return listener.Listener(request.param)


class TestListener(object):
    @pytest.mark.parametrize("listener_obj",
                             ALL_TEST_OBJ["interfaces"],
                             indirect=['listener_obj'])
    def test_init(self, listener_obj):
        return

    @pytest.mark.parametrize("listener_obj",
                             [pytest.param(
                                 x,
                                 marks=pytest.mark.xfail(
                                     raises=socket.error, strict=True))
                              for x in VALID_TEST_OBJ["interfaces"]],
                             indirect=['listener_obj']
                             )
    def test_connect_with_valid_interfaces(self, listener_obj):
        listener_obj.connect()
        return
