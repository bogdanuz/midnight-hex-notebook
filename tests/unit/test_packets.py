"""Тесты генерации пакетов и паддинга."""
import pytest
from src.core.packets.generator import (
    generate_junk_packet,
    generate_junk_burst,
    get_header_value,
    add_padding,
)
from src.core.protocol.config import AWGConfig


class TestJunkPacketGeneration:
    def test_packet_size_within_range(self) -> None:
        for _ in range(100):
            pkt = generate_junk_packet(40, 70)
            assert 40 <= len(pkt) <= 70, f"Размер {len(pkt)} вне диапазона [40,70]"

    def test_packet_content_is_random(self) -> None:
        pkts = [generate_junk_packet(64, 64) for _ in range(20)]
        unique = set(pkts)
        assert len(unique) > 10, "Пакеты неслучайны"

    def test_burst_count(self, awg15_config: AWGConfig) -> None:
        burst = generate_junk_burst(awg15_config)
        assert len(burst) == awg15_config.Jc

    def test_burst_packet_sizes(self, awg15_config: AWGConfig) -> None:
        burst = generate_junk_burst(awg15_config)
        for pkt in burst:
            assert awg15_config.Jmin <= len(pkt) <= awg15_config.Jmax

    def test_empty_burst_for_zero_jc(self, awg15_config: AWGConfig) -> None:
        awg15_config.Jc = 0
        burst = generate_junk_burst(awg15_config)
        assert burst == []


class TestAWG20Headers:
    def test_header_value_from_range(self) -> None:
        for _ in range(100):
            val = get_header_value([100, 199])
            assert 100 <= val <= 199

    def test_header_static_value_returned_as_is(self) -> None:
        assert get_header_value(42) == 42

    def test_header_values_unique_across_calls(self) -> None:
        vals = [get_header_value([100, 199]) for _ in range(50)]
        assert len(set(vals)) > 10, "Значения заголовков не случайны"


class TestPadding:
    def test_padding_adds_correct_bytes(self) -> None:
        data = b"\x01\x02\x03"
        padded = add_padding(data, 10)
        assert len(padded) == 13
        assert padded[:3] == data

    def test_zero_padding_returns_original(self) -> None:
        data = b"\x01\x02\x03"
        assert add_padding(data, 0) == data

    def test_s4_constraint(self) -> None:
        """S4 не может превышать 32 байта — проверка длины паддинга."""
        data = b"x" * 100
        padded = add_padding(data, 32)
        assert len(padded) == 132
