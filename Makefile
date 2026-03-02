.PHONY: install test test-unit test-integration lint clean run

install:
	pip install -e ".[dev]"

test:
	pytest tests/ -v --cov=src --cov-report=term-missing

test-unit:
	pytest tests/unit/ -v

test-integration:
	pytest tests/integration/ -v

lint:
	ruff check src/ tests/
	mypy src/ || true

clean:
	-del /s /q __pycache__ 2>nul || true
	-for /d /r . %%d in (__pycache__) do @rd /s /q "%%d" 2>nul || true
	-del /s /q *.pyc 2>nul || true
	-if exist dist rd /s /q dist
	-if exist build rd /s /q build
	-if exist .coverage del .coverage
	-if exist htmlcov rd /s /q htmlcov

run:
	python GenSpecialJunkPacket.py
