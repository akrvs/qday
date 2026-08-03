import socket
import threading

import pytest

from qday.cli import main
from qday.scanners.tls import _starttls_dialog


def _pair():
    server, client = socket.socketpair()
    server.settimeout(5)
    client.settimeout(5)
    return server, client


def _run_dialog(script, proto):
    server, client = _pair()
    errors = []

    def serve():
        try:
            script(server)
        except Exception as exc:
            errors.append(exc)

    t = threading.Thread(target=serve)
    t.start()
    try:
        _starttls_dialog(client, proto)
    finally:
        t.join(timeout=5)
        server.close()
        client.close()
    assert not errors


def test_smtp_dialog_multiline_ehlo():
    def script(s):
        f = s.makefile("rb")
        s.sendall(b"220 mail ready\r\n")
        assert f.readline().startswith(b"EHLO")
        s.sendall(b"250-mail.example\r\n250 STARTTLS\r\n")
        assert f.readline().strip() == b"STARTTLS"
        s.sendall(b"220 go ahead\r\n")

    _run_dialog(script, "smtp")


def test_imap_dialog():
    def script(s):
        f = s.makefile("rb")
        s.sendall(b"* OK imap ready\r\n")
        assert f.readline().strip() == b"q1 STARTTLS"
        s.sendall(b"q1 OK begin TLS\r\n")

    _run_dialog(script, "imap")


def test_pop3_refusal_raises():
    server, client = _pair()

    def serve():
        f = server.makefile("rb")
        server.sendall(b"+OK ready\r\n")
        f.readline()
        server.sendall(b"-ERR no tls\r\n")

    t = threading.Thread(target=serve)
    t.start()
    with pytest.raises(OSError):
        _starttls_dialog(client, "pop3")
    t.join(timeout=5)
    server.close()
    client.close()


def test_scan_rejects_bad_starttls_target(tmp_path):
    assert main(["--db", str(tmp_path / "t.db"), "scan",
                 "--starttls", "ftp:mail.example.com"]) == 2
    assert main(["--db", str(tmp_path / "t.db"), "scan",
                 "--starttls", "smtp:"]) == 2
