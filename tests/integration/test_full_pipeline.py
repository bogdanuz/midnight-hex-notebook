"""Интеграционные тесты полного пайплайна AWG 2.0."""
import pytest
from src.core.protocol.config import generate_awg20_config_defaults
from src.core.packets.generator import (
    generate_junk_burst,
    get_header_value,
    add_padding,
)


class TestFullAWG20Pipeline:
    def test_complete_awg20_connection_sequence(self) -> None:
        cfg = generate_awg20_config_defaults()
        assert cfg.validate() == []

        burst = generate_junk_burst(cfg)
        assert len(burst) == cfg.Jc or cfg.Jc == 0

        h1_val = get_header_value(cfg.H1)
        h2_val = get_header_value(cfg.H2)
        assert h1_val != h2_val or (cfg.H1 == cfg.H2)

        fake_init_msg = b"\x00" * 148
        padded = add_padding(fake_init_msg, cfg.S1)
        assert len(padded) == 148 + cfg.S1

        if cfg.version == "2.0":
            fake_cookie = b"\x00" * 64
            padded_cookie = add_padding(fake_cookie, cfg.S3)
            assert len(padded_cookie) == 64 + cfg.S3
            assert cfg.S4 <= 32

    def test_10_sequential_connections_produce_unique_headers(self) -> None:
        cfg = generate_awg20_config_defaults()
        header_sets = []
        for _ in range(10):
            h = (
                get_header_value(cfg.H1),
                get_header_value(cfg.H2),
                get_header_value(cfg.H3),
                get_header_value(cfg.H4),
            )
            header_sets.append(h)
        unique = set(header_sets)
        assert len(unique) > 5, "Заголовки не меняются между подключениями"
