"""
Test the main sniffer package
"""

import pytest


@pytest.fixture
def sniff(request):
    from sniffer import sniffer
    if request.param:
        return sniffer.Sniffer(request.param)
    else:
        return sniffer.Sniffer()


@pytest.fixture()
def test_output(request):
    return request.param


class TestSniffer(object):
    @pytest.mark.parametrize("sniff,test_output",
                             [
                                 (None, "eth0"),
                                 ("eth1", "eth1")
                             ],
                             indirect=['sniff']
                             )
    def test_init_empty(self, sniff, test_output):
        assert sniff.get_dev() == test_output
