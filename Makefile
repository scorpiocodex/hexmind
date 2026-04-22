.PHONY: install pull-model run test lint clean doctor

install:
	pip install -e .
	mkdir -p ~/.hexmind/logs
	cp config.toml ~/.hexmind/config.toml
	@echo "HexMind installed. Run 'make pull-model' next."

pull-model:
	ollama pull mistral

run:
	python3 -m hexmind.cli

test:
	python3 -m pytest tests/ -v

lint:
	python3 -m py_compile hexmind/cli.py \
	  hexmind/core/session.py \
	  hexmind/core/agentic_loop.py \
	  hexmind/recon/orchestrator.py \
	  hexmind/ai/engine.py \
	  hexmind/db/database.py \
	  hexmind/reports/exporter.py
	@echo "All files compile OK"

doctor:
	python3 -m hexmind.cli doctor

clean:
	find . -name "__pycache__" -exec rm -rf {} + 2>/dev/null; true
	find . -name "*.pyc" -delete 2>/dev/null; true
	rm -f /tmp/hexmind_* 2>/dev/null; true
	@echo "Cleaned."
