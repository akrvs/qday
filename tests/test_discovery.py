import socket
import threading

import pytest

from qday.discovery import DiscoveryError, discover, parse_spec


def test_parse_spec_cidr_and_ports():
    hosts, ports = parse_spec("10.0.0.0/30:443,8443")
    assert hosts == ["10.0.0.1", "10.0.0.2"]        # network/broadcast dropped
    assert ports == [443, 8443]


def test_parse_spec_port_range_and_default():
    hosts, ports = parse_spec("example.com")
    assert hosts == ["example.com"] and ports == [443]
    _, ports = parse_spec("h:8000-8003")
    assert ports == [8000, 8001, 8002, 8003]


def test_parse_spec_rejects_huge_range():
    with pytest.raises(DiscoveryError):
        parse_spec("10.0.0.0/8:443")            # /8 is way past the host cap


def test_discover_finds_only_open_ports():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    open_port = listener.getsockname()[1]

    # a port we can be confident is closed
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    closed_port = closed.getsockname()[1]
    closed.close()

    live = discover([f"127.0.0.1:{open_port},{closed_port}"])
    listener.close()

    assert f"127.0.0.1:{open_port}" in live
    assert f"127.0.0.1:{closed_port}" not in live
