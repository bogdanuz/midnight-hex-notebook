"""Простые проверки структуры web/index.html."""
from pathlib import Path


def read_index() -> str:
    return Path("web/index.html").read_text(encoding="utf-8")


class TestWebIndexStructure:
    def test_core_elements_present(self) -> None:
        html = read_index()
        assert 'id="refreshBtn"' in html
        for i in range(1, 6):
            assert f'id="i{i}"' in html
            assert f'data-target="i{i}"' in html

    def test_modal_elements_present(self) -> None:
        html = read_index()
        assert 'id="instructionBtn"' in html
        assert 'id="instructionModal"' in html
        assert 'id="modalClose"' in html
        assert 'Как использовать значения I1–I5' in html

    def test_available_files_one(self) -> None:
        html = read_index()
        assert 'let availableFiles = [1]' in html
