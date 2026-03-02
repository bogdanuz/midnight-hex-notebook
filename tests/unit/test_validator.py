"""Тесты валидатора AWG конфигурации."""
import pytest
from src.core.protocol.config import AWGConfig
from src.config.validator import validate_config


class TestAWGConfigValidation:
    def test_valid_awg15_config_passes(self, awg15_config: AWGConfig) -> None:
        errors = awg15_config.validate()
        assert errors == [], f"Неожиданные ошибки: {errors}"

    def test_valid_awg20_config_passes(self, awg20_config: AWGConfig) -> None:
        errors = awg20_config.validate()
        assert errors == [], f"Неожиданные ошибки: {errors}"

    def test_s1_plus_56_equals_s2_fails(self, invalid_config_s1s2: AWGConfig) -> None:
        errors = invalid_config_s1s2.validate()
        assert any(
            "S1+56" in e or "S1 + 56" in e for e in errors
        ), "Должна быть ошибка S1+56==S2"

    def test_s4_max_32(self) -> None:
        cfg = AWGConfig(
            version="2.0",
            S4=33,
            H1=[1, 2],
            H2=[3, 4],
            H3=[5, 6],
            H4=[7, 8],
        )
        errors = cfg.validate()
        assert any("S4" in e for e in errors)

    def test_jmin_greater_than_jmax_fails(self) -> None:
        cfg = AWGConfig(
            version="1.5",
            Jmin=100,
            Jmax=50,
            H1=1,
            H2=2,
            H3=3,
            H4=4,
        )
        errors = cfg.validate()
        assert any("Jmin" in e and "Jmax" in e for e in errors)

    def test_awg20_h_must_be_ranges(self) -> None:
        cfg = AWGConfig(
            version="2.0",
            H1=42,
            H2=43,
            H3=44,
            H4=45,
        )
        errors = cfg.validate()
        assert any(
            "диапазон" in e.lower() or "range" in e.lower() or "H1" in e
            for e in errors
        )

    def test_jmax_less_than_mtu(self) -> None:
        cfg = AWGConfig(
            version="1.5",
            Jmax=1500,
            H1=1,
            H2=2,
            H3=3,
            H4=4,
        )
        errors = cfg.validate()
        assert any("MTU" in e or "Jmax" in e for e in errors)


class TestGenerateDefaults:
    def test_generated_awg20_config_is_valid(self) -> None:
        from src.core.protocol.config import generate_awg20_config_defaults

        cfg = generate_awg20_config_defaults()
        errors = cfg.validate()
        assert errors == [], f"Сгенерированный конфиг невалиден: {errors}"

    def test_generated_config_randomness(self) -> None:
        """Каждый вызов должен давать разные параметры."""
        from src.core.protocol.config import generate_awg20_config_defaults

        configs = [generate_awg20_config_defaults() for _ in range(10)]
        h1_values = [str(c.H1) for c in configs]
        assert len(set(h1_values)) > 3, "H1 не меняется между генерациями"
