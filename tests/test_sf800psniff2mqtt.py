# -*- coding: utf-8 -*-
"""
pytest unit tests
"""
from io import StringIO


from sf800p2mqtt.sf800psniff2mqtt import has_cap_net_raw

# pylint: disable=missing-function-docstring, missing-module-docstring, unused-argument,missing-class-docstring


# Run tests with logging DEBUG
# pytest -o log_cli_level=DEBUG -o log_cli_handler=stream -o log_cli=1


class TestCheckCapNetRaw:
    @staticmethod
    def test_no_file(monkeypatch):
        """Test that has_cap_net_raw returns False if /proc/self/status is not found."""
        def open_fail(*args, **kwargs):
            raise FileNotFoundError
        monkeypatch.setattr("builtins.open", open_fail)
        assert has_cap_net_raw() is False

    @staticmethod
    def test_cap_net_raw_set(monkeypatch):
        """Test that has_cap_net_raw returns True when CAP_NET_RAW bit is set in CapEff."""
        # CAP_NET_RAW = 1 << 13 = 8192 → hex 0x2000
        fake_file = StringIO("Name:\tsome_process\nCapEff:\t2000\nState:\tR (running)\n")
        monkeypatch.setattr("builtins.open", lambda *args, **kwargs: fake_file)
        assert has_cap_net_raw() is True

    @staticmethod
    def test_cap_net_raw_unset(monkeypatch):
        """Test that has_cap_net_raw returns False when CAP_NET_RAW bit is not set in CapEff."""
        # Example hex value without bit 13 set, e.g. 0x1000
        fake_file = StringIO("Name:\tsome_process\nCapEff:\t1000\nState:\tR (running)\n")
        monkeypatch.setattr("builtins.open", lambda *args, **kwargs: fake_file)
        assert has_cap_net_raw() is False

    @staticmethod
    def test_no_capeff_line(monkeypatch):
        """Test that has_cap_net_raw returns False if CapEff line is missing."""
        fake_file = StringIO("Name:\tsome_process\nState:\tR (running)\n")
        monkeypatch.setattr("builtins.open", lambda *args, **kwargs: fake_file)
        assert has_cap_net_raw() is False
